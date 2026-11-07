//! Actual CADET channel/source generations, delivery debts and immutable writes.
use super::*;
impl<'id, 'slots> Server<'id, 'slots> {
    fn pending_channel(&self) -> Option<cadet::Channel<'id>> {
        match self.pending.as_ref()?.kind {
            PendingKind::Open(c)
            | PendingKind::Send(c)
            | PendingKind::Destroy(c)
            | PendingKind::Ack(c) => Some(c),
            _ => None,
        }
    }
    fn mark_channel(&mut self, index: usize) -> Result<(), Error> {
        let hard = self.hard()?;
        let channel = self.channels[index].as_mut().ok_or(Fault::Stale)?;
        channel.mark_closing(hard);
        Ok(())
    }
    fn reject_peer(
        &mut self,
        index: usize,
        error: Fault,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let channel = self.channels[index].as_ref().ok_or(Fault::Stale)?;
        observe(Event::PeerRefused {
            listener: channel.listener,
            owner: channel.owner,
            peer: channel.peer,
            error,
        });
        self.channels[index]
            .as_mut()
            .ok_or(Fault::Stale)?
            .retire_reason = error;
        self.mark_channel(index)
    }
    pub(super) fn finish_channel(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let channel = self.channels[index].as_ref().ok_or(Fault::Stale)?;
        let (original, owner, reason) = (channel.channel, channel.owner, channel.retire_reason);
        if self
            .adopted
            .as_ref()
            .is_some_and(|a| a.channel == Some(original))
        {
            self.settle_adopt(observe)?;
        }
        let mut at = 0;
        while at < self.sends.len() {
            if self.sends[at].channel == original {
                let id = self.sends[at].id;
                self.terminal(id, Completion::Unsent(reason), true, observe)?;
                let _removed = self.sends.remove(at);
            } else {
                at += 1;
            }
        }
        // This exact native generation is physically gone and every original
        // send has a real terminal before retiring its original pure peer slot.
        if let Some(owner) = owner {
            match self.core.peer_lost(owner, reason) {
                Ok(()) | Err(Fault::StaleGeneration) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.channels[index] = None;
        Ok(())
    }
    fn input(&mut self, index: usize, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        let channel = self.channels[index].as_ref().ok_or(Fault::Stale)?;
        if channel.local_closing
            || self
                .adopted
                .as_ref()
                .is_some_and(|a| a.channel == Some(channel.channel))
        {
            return Ok(false);
        }
        let Some(input) = &channel.input else {
            return Ok(false);
        };
        // Only an already adopted original operation may consume DATA received
        // before physical peer retirement. A gone source cannot publish a new
        // incoming offer, accept authority or route bytes to a replacement owner.
        if channel.remote_closed && !matches!(channel.owner, Some(PeerOwner::Operation(_))) {
            self.channels[index].as_mut().ok_or(Fault::Stale)?.input = None;
            return Ok(true);
        }
        if input.at == input.packet.messages().len() {
            if channel.remote_closed {
                // This original Delivery's channel is gone. Release only held
                // local bytes; never issue a new receive_done/ACK on that source.
                self.channels[index].as_mut().ok_or(Fault::Stale)?.input = None;
                return Ok(true);
            }
            // The initial operation request holds its original receive credit
            // until the local ACCEPT actually adopts this same channel. Early
            // credit could let a normal peer send algorithm data before the
            // pending incoming owner can route it.
            if matches!(channel.owner, Some(PeerOwner::Incoming(_))) {
                return Ok(false);
            }
            if self.cadet.pending_transmit().is_some() {
                return Ok(false);
            }
            let (delivery, original) = (input.packet.delivery(), channel.channel);
            let hard = self.hard()?;
            return match self.cadet.receive_done(delivery) {
                Ok(transmit) => {
                    self.pending(transmit, None, PendingKind::Ack(original), hard)?;
                    self.channels[index].as_mut().ok_or(Fault::Stale)?.input = None;
                    Ok(true)
                }
                Err(error) if retry(&error) => Ok(false),
                Err(error) => Err(error.into()),
            };
        }
        // Freeze one original message's logical admission instant. Retries keep
        // the same bytes, owner and first-byte physical hard deadline.
        let first_attempt = input.held_now.is_none();
        let now = match input.held_now {
            Some(now) => now,
            None => {
                let now = self.now()?;
                self.channels[index]
                    .as_mut()
                    .and_then(|c| c.input.as_mut())
                    .ok_or(Fault::Stale)?
                    .held_now = Some(now);
                now
            }
        };
        let channel = self.channels[index].as_ref().ok_or(Fault::Stale)?;
        let input = channel.input.as_ref().ok_or(Fault::Stale)?;
        let parsed = (|| {
            let tail = input
                .packet
                .messages()
                .get(input.at..)
                .ok_or(Fault::Malformed)?;
            let header = MessageHeader::decode(tail)?;
            let n = header.size();
            let frame = tail.get(..n).ok_or(Fault::Truncated)?;
            // All old SET layout choices are the explicitly selected service ABI.
            let message = PeerMessage::decode(frame, self.core.abi())?;
            Ok::<_, Fault>((message, frame, n))
        })();
        let (message, frame, n) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                self.reject_peer(index, error, observe)?;
                return Ok(true);
            }
        };
        let mut incoming = None;
        let result = if let Some(owner) = input.owner {
            if channel.owner != Some(owner) {
                return Err(Fault::StaleGeneration.into());
            }
            self.core
                .receive(owner, frame, now, &mut self.ports_provider)
        } else {
            let listener = channel.listener.ok_or(Fault::StaleGeneration)?;
            // Application authority is the original actual CADET port, never
            // OperationRequest.app_id (normal C union/intersection leave it 0).
            match self.core.incoming(
                listener,
                channel.peer,
                channel.app_id,
                message,
                now,
                &mut self.ports_provider,
            ) {
                Ok(owner) => {
                    incoming = Some(owner);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        };
        // The first receive may retain deferred algorithm input and return
        // NotReady. Restart once for this exact held message, even though no
        // native class reports progress. Repeated retries keep held_now and
        // cannot continually renew the CPU pass.
        if first_attempt {
            self.restart_progress();
        }
        match self.core_result(result) {
            Ok(()) => {
                let channel = self.channels[index].as_mut().ok_or(Fault::Stale)?;
                let input = channel.input.as_mut().ok_or(Fault::Stale)?;
                if let Some(incoming) = incoming {
                    let owner = PeerOwner::Incoming(incoming);
                    channel.owner = Some(owner);
                    input.owner = Some(owner);
                    channel.first = None;
                }
                input.at = input.at.checked_add(n).ok_or(Fault::Overflow)?;
                input.held_now = None;
                if incoming.is_some() && input.at == input.packet.messages().len() {
                    // Fully classified request now waits for the core's fixed
                    // accept lifetime, not an already finished partial-input phase.
                    input.hard = None;
                }
                Ok(true)
            }
            Err(Error::Protocol(Fault::WouldBlock | Fault::NotReady)) => {
                // This first classification is finite bookkeeping work even if
                // the CPU class was already visited earlier in the same poll.
                // It keeps the new pass eligible without claiming an ACK.
                Ok(first_attempt)
            }
            Err(Error::Protocol(error)) => {
                self.reject_peer(index, error, observe)?;
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }
    fn settle_closing(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        for i in 0..self.closing.len() {
            let close = &self.closing[i];
            if self
                .channels
                .iter()
                .flatten()
                .any(|c| c.owner == Some(close.owner))
            {
                continue;
            }
            let (id, outcome) = (
                close.id,
                close.outcome.unwrap_or(if close.written {
                    Completion::Written
                } else {
                    Completion::Unsent(Fault::Closed)
                }),
            );
            self.terminal(id, outcome, true, observe)?;
            self.closing.remove(i);
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn settle_all_closing(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let count = self.closing.len();
        for _ in 0..count {
            if !self.settle_closing(observe)? {
                break;
            }
        }
        Ok(())
    }
    pub(super) fn retire_unannounced_ports(
        &mut self,
        reason: Fault,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        // Before another native poll can automatically reannounce a desired
        // port, remove a canceled still-unannounced one through the actual
        // clock-free native retirement API. Never race an original frame.
        if self.pending.is_some() || self.cadet.pending_transmit().is_some() {
            return Ok(false);
        }
        for index in 0..self.ports.len() {
            let Some(bound) = &self.ports[index] else {
                continue;
            };
            if !bound.closing
                || self
                    .channels
                    .iter()
                    .flatten()
                    .any(|c| c.listener == Some(bound.listener))
            {
                continue;
            }
            let (port, effect) = (bound.port, bound.close);
            if self.cadet.epoch().is_some()
                && self.cadet.port_hash(port).is_ok()
                && self.cadet.port_announced(port)?
            {
                continue;
            }
            if self.cadet.port_hash(port).is_ok() {
                match self.cadet.close_port(port) {
                    Ok(None) => {}
                    Ok(Some(_)) => return Err(Fault::Conflict.into()),
                    Err(cadet::Error::Protocol(Fault::Closed)) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if let Some(id) = effect {
                self.terminal(id, Completion::Unsent(reason), true, observe)?;
            }
            self.ports[index] = None;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn peer_work(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        if self.settle_closing(observe)? {
            return Ok(true);
        }
        for offset in 0..self.channels.len() {
            let index = (self.peer_cursor + offset) % self.channels.len();
            let Some(channel) = &self.channels[index] else {
                continue;
            };
            if channel.remote_closed {
                // Classify only the already held original DATA before the
                // physical-retirement callback. Core backpressure retains the
                // same cursor/held_now/hard while other MQ work remains eligible.
                if self.input(index, observe)? {
                    self.peer_cursor = (index + 1) % self.channels.len();
                    return Ok(true);
                }
                let channel = self.channels[index].as_ref().ok_or(Fault::Stale)?;
                if channel.input.is_some() {
                    continue;
                }
                if self.pending_channel() != Some(channel.channel) {
                    self.finish_channel(index, observe)?;
                    self.peer_cursor = (index + 1) % self.channels.len();
                    return Ok(true);
                }
                continue;
            }
            if self.input(index, observe)? {
                self.peer_cursor = (index + 1) % self.channels.len();
                return Ok(true);
            }
        }
        if self.cadet.pending_transmit().is_some() {
            return Ok(false);
        }
        for index in 0..self.channels.len() {
            let Some(channel) = &self.channels[index] else {
                continue;
            };
            if !channel.closing || channel.remote_closed {
                continue;
            }
            let original = channel.channel;
            // The first local close owns this finite cleanup target. Retrying
            // a blocked Destroy must not create a fresh write/cleanup lifetime.
            let hard = channel.hard.ok_or(Fault::Stale)?;
            match self.cadet.destroy(original) {
                Ok(transmit) => {
                    self.pending(transmit, None, PendingKind::Destroy(original), hard)?;
                    return Ok(true);
                }
                Err(cadet::Error::Protocol(Fault::StaleGeneration | Fault::Stale)) => {
                    self.finish_channel(index, observe)?;
                    return Ok(true);
                }
                Err(error) if retry(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        for index in 0..self.ports.len() {
            let Some(bound) = &self.ports[index] else {
                continue;
            };
            if !bound.closing
                || self
                    .channels
                    .iter()
                    .flatten()
                    .any(|c| c.listener == Some(bound.listener))
            {
                continue;
            }
            let (listener, port, id) = (bound.listener, bound.port, bound.close);
            if self.cadet.port_hash(port).is_err() {
                if let Some(id) = id {
                    self.terminal(id, Completion::Unsent(Fault::Closed), true, observe)?;
                }
                self.ports[index] = None;
                return Ok(true);
            }
            let hard = self.hard()?;
            match self.cadet.close_port(port) {
                Ok(Some(transmit)) => {
                    // The existing ClosePort effect was admitted when this host
                    // accepted its actual retirement debt, not a second time.
                    self.pending = Some(Pending {
                        transmit,
                        effect: id,
                        admitted: true,
                        kind: PendingKind::ClosePort(listener),
                        hard,
                        completion: None,
                    });
                    self.ports[index].as_mut().ok_or(Fault::Stale)?.close = None;
                    return Ok(true);
                }
                Ok(None) => {
                    if let Some(id) = id {
                        self.terminal(id, Completion::Unsent(Fault::Closed), true, observe)?;
                    }
                    self.ports[index] = None;
                    return Ok(true);
                }
                Err(error) if retry(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        for i in 0..self.sends.len() {
            let send = &self.sends[i];
            let Some(index) = self.channel_index(send.channel) else {
                let id = send.id;
                self.terminal(id, Completion::Unsent(Fault::Closed), true, observe)?;
                let _removed = self.sends.remove(i);
                return Ok(true);
            };
            let channel = self.channels[index].as_ref().ok_or(Fault::Stale)?;
            if channel.closing {
                let id = send.id;
                self.terminal(id, Completion::Unsent(Fault::Cancelled), true, observe)?;
                let _removed = self.sends.remove(i);
                return Ok(true);
            }
            if channel.opening || self.sends.iter().take(i).any(|s| s.channel == send.channel) {
                continue;
            }
            let (id, original, hard) = (send.id, send.channel, send.hard);
            match self.cadet.send(original, 0, send.frame.bytes()) {
                Ok(transmit) => {
                    self.pending = Some(Pending {
                        transmit,
                        effect: Some(id),
                        admitted: true,
                        kind: PendingKind::Send(original),
                        hard,
                        completion: None,
                    });
                    let _removed = self.sends.remove(i);
                    return Ok(true);
                }
                Err(error) if retry(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(false)
    }
    fn written(
        &mut self,
        written: cadet::Written<'id>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        if let Some(pending) = &mut self.pending {
            if pending.transmit != written.transmit {
                return Err(Fault::Stale.into());
            }
            pending.completion = Some(Completion::Written);
            self.settle_pending(observe)?;
        }
        Ok(())
    }
    pub(super) fn lost(
        &mut self,
        report: cadet::Loss<'id>,
        cause: cadet::LossCause,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let forced = self.forced_loss.take();
        let reason = forced.map_or_else(
            || match &cause {
                // A local CADET service MQ disappearing is not a particular
                // authenticated peer/channel closing its completed SET protocol.
                cadet::LossCause::Eof => Fault::Unavailable,
                cadet::LossCause::Io(_) => Fault::Io,
                cadet::LossCause::Protocol(Fault::Closed) => Fault::Unavailable,
                cadet::LossCause::Protocol(error) => *error,
                cadet::LossCause::Requested => Fault::Cancelled,
            },
            |forced| forced.reason,
        );
        let pending_report = report.pending;
        self.report.cadet_losses = self.report.cadet_losses.saturating_add(1);
        self.read_hard = None;
        observe(Event::CadetLost {
            report,
            cause,
            forced,
        });
        if let Some(pending) = &mut self.pending {
            let completion = match pending_report {
                Some(retired) if retired.transmit == pending.transmit && !retired.exposed => {
                    Completion::Unsent(reason)
                }
                _ => Completion::Lost(reason),
            };
            pending.completion.get_or_insert(completion);
        }
        // Classify all original physical sources before completion hooks can
        // retire a channel. In particular a pending Destroy that was not fully
        // written cannot use an old default Closed to turn MQ loss into success.
        for channel in self.channels.iter_mut().flatten() {
            channel.retire_reason = reason;
        }
        for close in &mut self.closing {
            if !close.written {
                close.outcome.get_or_insert(Completion::Lost(reason));
            }
        }
        self.settle_adopt(observe)?;
        self.settle_pending(observe)?;
        for i in 0..self.channels.len() {
            if self.channels[i].is_some() {
                self.finish_channel(i, observe)?;
            }
        }
        Ok(())
    }
    pub(super) fn native_event(
        &mut self,
        event: cadet::Step<'id>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        match event {
            cadet::Step::Written(written) => self.written(written, observe)?,
            cadet::Step::Incoming { channel, port } => {
                self.read_hard = None;
                let Some(index) = self.channels.iter().position(Option::is_none) else {
                    observe(Event::AdmissionFailed(Fault::Capacity.into()));
                    self.force_retirement(
                        Fault::Capacity,
                        RetirementTrigger::IncomingCapacity {
                            channel: channel.value(),
                            wire: channel.wire_id(),
                        },
                    );
                    let event = self.cadet.reconnect()?;
                    self.native_event(event, observe)?;
                    return Ok(true);
                };
                let info = self.cadet.channel_info(channel)?;
                let Some(bound) = self
                    .ports
                    .iter()
                    .flatten()
                    .find(|p| p.port == port && p.hash == info.port)
                else {
                    observe(Event::AdmissionFailed(Fault::StaleGeneration.into()));
                    self.force_retirement(
                        Fault::StaleGeneration,
                        RetirementTrigger::IncomingPortMismatch {
                            channel: channel.value(),
                            wire: channel.wire_id(),
                        },
                    );
                    let event = self.cadet.reconnect()?;
                    self.native_event(event, observe)?;
                    return Ok(true);
                };
                let listener = bound.listener;
                let app_id = bound.hash;
                let closing = bound.closing || !self.core.client_live(listener);
                let peer = info.peer;
                let hard = Instant::now()
                    .checked_add(self.limits.first_input)
                    .ok_or(Fault::Overflow)?;
                let mut incoming = Channel {
                    listener: Some(listener),
                    app_id,
                    owner: None,
                    peer,
                    channel,
                    opening: false,
                    closing: false,
                    local_closing: false,
                    remote_closed: false,
                    input: None,
                    hard: None,
                    first: Some(hard),
                    retire_reason: Fault::Closed,
                };
                if closing {
                    incoming.mark_closing(self.hard()?);
                }
                self.channels[index] = Some(incoming);
                // Only a successfully admitted original operation request creates
                // an Incoming capability. Channel creation alone is no SET ACK.
            }
            cadet::Step::Data(packet) => {
                self.read_hard = None;
                let channel = packet.channel();
                let hard = Instant::now()
                    .checked_add(self.limits.partial_input)
                    .ok_or(Fault::Overflow)?;
                let Some(index) = self.channel_index(channel) else {
                    return Err(Fault::Stale.into());
                };
                let source = self.channels[index].as_mut().ok_or(Fault::Stale)?;
                if source.closing {
                    // Local close already revoked input, or a previous actual
                    // Destroyed retired this channel. Do not create new debt or
                    // revive input/receive credit on either closed path.
                    return Ok(true);
                }
                if source.input.is_some() {
                    return Err(Fault::Conflict.into());
                }
                source.input = Some(Input {
                    packet,
                    at: 0,
                    hard: Some(hard),
                    held_now: None,
                    owner: source.owner,
                });
            }
            cadet::Step::Destroyed(channel) => {
                self.read_hard = None;
                let hard = self.hard()?;
                if let Some(index) = self.channel_index(channel) {
                    let source = self.channels[index].as_mut().ok_or(Fault::Stale)?;
                    // Preserve a previously received original Input. This does
                    // not set local_closing or cancel an already admitted native
                    // suffix: it keeps its actual terminal and original hard.
                    // Local close paths discarded theirs via mark_closing.
                    source.closing = true;
                    source.remote_closed = true;
                    source.first = None;
                    source.hard.get_or_insert(hard);
                }
            }
            cadet::Step::Lost { report, cause, .. } => self.lost(report, cause, observe)?,
            cadet::Step::Connected(_) => {
                self.read_hard = None;
            }
            cadet::Step::ConnectRetry { error, retry_after } => {
                observe(Event::CadetRetry { error, retry_after })
            }
            cadet::Step::Unavailable(error) => return Err(error.into()),
            cadet::Step::Blocked { .. } => {
                let hard = Instant::now()
                    .checked_add(self.limits.partial_input)
                    .ok_or(Fault::Overflow)?;
                self.read_hard.get_or_insert(hard);
                return Ok(false);
            }
            cadet::Step::Activity { read_bytes, .. } => {
                if read_bytes > 0 {
                    let hard = Instant::now()
                        .checked_add(self.limits.partial_input)
                        .ok_or(Fault::Overflow)?;
                    self.read_hard.get_or_insert(hard);
                }
            }
            cadet::Step::Credit { .. }
            | cadet::Step::RejectedIncoming { .. }
            | cadet::Step::Ignored { .. } => self.read_hard = None,
            cadet::Step::WaitDeadline => return Ok(false),
            cadet::Step::Closed => return Err(Fault::Closed.into()),
        }
        Ok(true)
    }
    pub(super) fn poll_cadet(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let hard = self.hard()?;
        let result = self.cadet.poll(cx, None);
        if self.pending.is_none()
            && let Some(transmit) = self.cadet.pending_transmit()
        {
            self.pending(transmit, None, PendingKind::Internal, hard)?;
        }
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(event)) => {
                if self.native_event(event, observe)? {
                    Poll::Ready(Ok(Progress::Activity))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}
