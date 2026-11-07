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
        channel.closing = true;
        channel.hard.get_or_insert(hard);
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
            group: channel.group,
            peer: channel.peer,
            error,
        });
        self.mark_channel(index)
    }
    pub(super) fn finish_channel(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let channel = self.channels[index].as_ref().ok_or(Fault::Stale)?;
        let (original, group, peer, qualification_retired) = (
            channel.channel,
            channel.group,
            channel.peer,
            channel.qualification_retired,
        );
        let mut at = 0;
        while at < self.sends.len() {
            if self.sends[at].channel == original {
                let id = self.sends[at].id;
                self.terminal(id, Completion::Unsent(Fault::Closed), true, observe)?;
                let _removed = self.sends.remove(at);
            } else {
                at += 1;
            }
        }
        // Another original owner may still hold a pre-close PULL reply. Keep
        // that scope until its qualification actually retires, even if physical
        // Destroyed already arrived; retired old owners cannot block a fresh one.
        if !qualification_retired
            && !self.channels.iter().enumerate().any(|(i, c)| {
                i != index
                    && c.as_ref().is_some_and(|c| {
                        c.group == group && c.peer == peer && !c.qualification_retired
                    })
            })
        {
            match self.core.peer_lost(group, peer) {
                Ok(()) | Err(Fault::StaleGeneration) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.channels[index] = None;
        Ok(())
    }
    fn input(&mut self, index: usize, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        let channel = self.channels[index].as_ref().ok_or(Fault::Stale)?;
        if channel.closing || channel.qualification_retired {
            if channel.input.is_some() {
                // Local revocation or completed qualification retirement makes
                // all this old owner's remaining input ineligible. It cannot
                // match a fresh same-peer pull after the old source retired.
                self.channels[index].as_mut().ok_or(Fault::Stale)?.input = None;
                return Ok(true);
            }
            return Ok(false);
        }
        let Some(input) = &channel.input else {
            return Ok(false);
        };
        if input.at == input.packet.messages().len() {
            if channel.remote_closed {
                self.channels[index].as_mut().ok_or(Fault::Stale)?.input = None;
                return Ok(true);
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
        let tail = input
            .packet
            .messages()
            .get(input.at..)
            .ok_or(Fault::Malformed)?;
        let parsed = (|| {
            let header = MessageHeader::decode(tail)?;
            let n = header.size();
            let frame = tail.get(..n).ok_or(Fault::Truncated)?;
            Ok::<_, Fault>((PeerMessage::decode(frame)?, n))
        })();
        let (message, n) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                self.reject_peer(index, error, observe)?;
                return Ok(true);
            }
        };
        let (group, peer) = (channel.group, channel.peer);
        let last_source_gone = channel.remote_closed
            && !self.channels.iter().enumerate().any(|(i, source)| {
                i != index
                    && source.as_ref().is_some_and(|source| {
                        source.group == group
                            && source.peer == peer
                            && !source.closing
                            && !source.remote_closed
                    })
            });
        let retires_sender = last_source_gone && matches!(message, PeerMessage::PullReply { .. });
        let now = self.now()?;
        let result = if last_source_gone {
            match message {
                PeerMessage::PullReply { peers } => self
                    .core
                    .peer_pull_reply_after_close(group, peer, peers, now),
                // Sender-only observations cannot revive a gone peer and a
                // PULL request cannot be answered on the destroyed channel.
                _ => Ok(()),
            }
        } else {
            self.core
                .peer_message(group, peer, message, now, &mut self.random, &mut self.rank)
        };
        match self.core_result(result) {
            Ok(()) => {
                if retires_sender {
                    // The atomic core transition already removed qualification.
                    // Only these original native owners retire here; their late
                    // callbacks must not erase a subsequent fresh peer probe.
                    for source in self.channels.iter_mut().flatten() {
                        if source.group == group && source.peer == peer {
                            source.qualification_retired = true;
                        }
                    }
                }
                let input = self.channels[index]
                    .as_mut()
                    .and_then(|c| c.input.as_mut())
                    .ok_or(Fault::Stale)?;
                input.at = input.at.checked_add(n).ok_or(Fault::Overflow)?;
                Ok(true)
            }
            Err(Error::Protocol(Fault::WouldBlock | Fault::NotReady)) => Ok(false),
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
                .any(|c| c.group == close.group && c.peer == close.peer)
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
            self.seed_cursor = Some(0);
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
    pub(super) fn retire_detached_ports(
        &mut self,
        reason: Fault,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        if self.cadet.epoch().is_some() {
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
                    .any(|c| c.group == bound.group)
            {
                continue;
            }
            let (port, effect) = (bound.port, bound.close);
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
                let original = channel.channel;
                if self.input(index, observe)? {
                    self.peer_cursor = (index + 1) % self.channels.len();
                    return Ok(true);
                }
                if self.channels[index]
                    .as_ref()
                    .is_some_and(|c| c.input.is_some())
                {
                    continue;
                }
                if self.pending_channel() != Some(original) {
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
            let hard = self.hard()?;
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
                    .any(|c| c.group == bound.group)
            {
                continue;
            }
            let (group, port, id) = (bound.group, bound.port, bound.close);
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
                        kind: PendingKind::ClosePort(group),
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
            if channel.closing || channel.remote_closed {
                let id = send.id;
                let cause = if channel.remote_closed {
                    Fault::Closed
                } else {
                    Fault::Cancelled
                };
                self.terminal(id, Completion::Unsent(cause), true, observe)?;
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
        if written.transmit.kind() == cadet::TransmitKind::PortOpen {
            // A real automatic reannouncement may have been tracked as Internal
            // while its immutable frame was partial. Both paths owe fresh
            // probes after this exact whole-write, never merely Connected.
            self.seed_cursor = Some(0);
        }
        Ok(())
    }
    pub(super) fn lost(
        &mut self,
        report: cadet::Loss<'id>,
        cause: cadet::LossCause,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let reason = self.forced_loss.take().unwrap_or(match &cause {
            cadet::LossCause::Eof => Fault::Closed,
            cadet::LossCause::Io(_) => Fault::Io,
            cadet::LossCause::Protocol(error) => *error,
            cadet::LossCause::Requested => Fault::Cancelled,
        });
        let pending_report = report.pending;
        self.report.cadet_losses = self.report.cadet_losses.saturating_add(1);
        self.read_hard = None;
        self.seed_cursor = None;
        observe(Event::CadetLost { report, cause });
        if let Some(pending) = &mut self.pending {
            let completion = match pending_report {
                Some(retired) if retired.transmit == pending.transmit && !retired.exposed => {
                    Completion::Unsent(reason)
                }
                _ => Completion::Lost(reason),
            };
            pending.completion.get_or_insert(completion);
        }
        self.settle_pending(observe)?;
        for close in &mut self.closing {
            close.outcome.get_or_insert(Completion::Lost(reason));
        }
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
                    self.forced_loss = Some(Fault::Capacity);
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
                    self.forced_loss = Some(Fault::StaleGeneration);
                    let event = self.cadet.reconnect()?;
                    self.native_event(event, observe)?;
                    return Ok(true);
                };
                let group = bound.group;
                let closing = bound.closing;
                let peer = info.peer;
                self.channels[index] = Some(Channel {
                    group,
                    peer,
                    channel,
                    opening: false,
                    closing: false,
                    remote_closed: false,
                    qualification_retired: false,
                    input: None,
                    hard: None,
                });
                if closing || self.core.group_hash(group).is_err() {
                    self.mark_channel(index)?;
                    return Ok(true);
                }
                let now = self.now()?;
                let result =
                    self.core
                        .peer_connected(group, peer, now, &mut self.random, &mut self.rank);
                match self.core_result(result) {
                    Ok(()) => {}
                    Err(Error::Protocol(error)) => self.reject_peer(index, error, observe)?,
                    Err(error) => return Err(error),
                }
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
                if source.input.is_some() {
                    return Err(Fault::Conflict.into());
                }
                source.input = Some(Input {
                    packet,
                    at: 0,
                    hard,
                });
            }
            cadet::Step::Destroyed(channel) => {
                self.read_hard = None;
                let hard = self.hard()?;
                if let Some(index) = self.channel_index(channel) {
                    let source = self.channels[index].as_mut().ok_or(Fault::Stale)?;
                    // Physical remote close is distinct from local revocation:
                    // preserve earlier input without permitting new peer IO.
                    source.remote_closed = true;
                    source.hard.get_or_insert(hard);
                }
            }
            cadet::Step::Lost { report, cause, .. } => self.lost(report, cause, observe)?,
            cadet::Step::Connected(_) => {
                self.read_hard = None;
                self.seed_cursor = Some(0);
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
