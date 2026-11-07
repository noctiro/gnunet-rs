//! One actual CADET MQ; original channels, packets and outer processing debts.
use super::*;
impl<'cfg, 'id, 'slots, E: Entropy> Driver<'cfg, 'id, 'slots, E> {
    pub(super) fn effect(
        &mut self,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let Some(effect) = self.engine.effect() else {
            return Ok(false);
        };
        match effect {
            core::Effect::Close { flow } => {
                if let Some(i) = self.flow(&flow) {
                    self.closing(i)?;
                    self.cancel_flow_tun(&flow, observe)?;
                } else {
                    self.engine.closed(&flow)?;
                }
            }
            core::Effect::Processed { flow, input } => {
                if let Some(i) = self.flow(&flow) {
                    let outer = self.peers[i]
                        .as_mut()
                        .and_then(|p| p.input.as_mut())
                        .ok_or(Fault::Stale)?;
                    if outer.pending.as_ref() != Some(&input) {
                        return Err(Fault::Stale.into());
                    }
                    outer.ready = true;
                } else {
                    self.engine.processing_retired(&input)?;
                }
            }
            core::Effect::CloseSource { .. } => self.close_cadet(observe)?,
            core::Effect::CloseTun { .. } => {
                if let Some(t) = &mut self.tun {
                    let loss = t.close();
                    self.tun_loss(loss, observe)?;
                }
            }
            core::Effect::DnsQuery {
                flow,
                job,
                packet,
                expires,
            } => {
                let query = OwnedFrame::copy_from(packet)?;
                self.dns_start(flow, job, query, expires, now, observe)?;
            }
            core::Effect::DnsCancel { job } => {
                if let Some(i) = self
                    .dns_jobs
                    .iter()
                    .position(|d| d.as_ref().is_some_and(|d| d.job == job))
                {
                    self.cancel_dns(i, None, observe)?;
                } else {
                    self.engine.dns_retired(&job, None)?;
                }
            }
        }
        Ok(true)
    }
    fn inner(&mut self, i: usize, now: MonoInstant) -> Result<bool, Error> {
        let p = self.peers[i].as_ref().ok_or(Fault::Stale)?;
        if p.closing {
            return Ok(false);
        }
        let flow = p.flow.as_ref().ok_or(Fault::Stale)?.clone();
        if self.engine.info(&flow)?.closing {
            // The original core deadline/cancellation wins before any more
            // held bytes are admitted, including after a remote close.
            self.closing(i)?;
            return Ok(true);
        }
        let Some(outer) = &p.input else {
            return Ok(false);
        };
        if let Some(input) = &outer.pending {
            if !outer.ready {
                return Ok(false);
            }
            let input = input.clone();
            match self.engine.processing_batched(&input) {
                Ok(()) => {
                    let outer = self.peers[i]
                        .as_mut()
                        .and_then(|p| p.input.as_mut())
                        .ok_or(Fault::Stale)?;
                    outer.receipts.push(input);
                    outer.at = outer.next;
                    outer.pending = None;
                    outer.ready = false;
                    return Ok(true);
                }
                Err(Fault::WouldBlock) => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
        if outer.at == outer.packet.messages().len() {
            if p.remote_closed {
                // Every original inner reached its real forwarding receipt.
                // The gone Delivery cannot authorize a new receive_done. Keep
                // any already admitted original MQ action until its terminal.
                if self
                    .pending
                    .as_ref()
                    .is_some_and(|pending| Self::action_channel(&pending.action) == Some(p.channel))
                {
                    return Ok(false);
                }
                self.finish_peer(i)?;
                return Ok(true);
            }
            if self.cadet.pending_transmit().is_some() {
                return Ok(false);
            }
            let delivery = outer.packet.delivery();
            let channel = p.channel;
            let started = Instant::now();
            match self.cadet.receive_done(delivery) {
                Ok(transmit) => {
                    let outer = self.peers[i]
                        .as_mut()
                        .and_then(|p| p.input.take())
                        .ok_or(Fault::Stale)?;
                    self.pending(
                        transmit,
                        Action::Ack {
                            channel,
                            receipts: outer.receipts,
                        },
                        started,
                    )?;
                    return Ok(true);
                }
                Err(e) if retry(&e) => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
        let tail = &outer.packet.messages()[outer.at..];
        let (frame, _) = Frame::decode_prefix(tail)?;
        let size = frame.encoded_len();
        match self
            .engine
            .receive(&flow, &tail[..size], now, &mut self.entropy)
        {
            Ok(input) => {
                let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                p.first = None;
                let outer = p.input.as_mut().ok_or(Fault::Stale)?;
                outer.next = outer.at + size;
                outer.pending = Some(input);
                Ok(true)
            }
            Err(Fault::WouldBlock) => Ok(false),
            Err(_) => {
                self.closing(i)?;
                Ok(true)
            }
        }
    }
    pub(super) fn peer_work(
        &mut self,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        if let Some(p) = &self.tun_held
            && self.engine.info(&p.flow)?.closing
        {
            let flow = p.flow.clone();
            self.cancel_flow_tun(&flow, observe)?;
            return Ok(true);
        }
        if let Some(p) = &self.tun_pending
            && self.engine.info(&p.flow)?.closing
        {
            let flow = p.flow.clone();
            self.cancel_flow_tun(&flow, observe)?;
            return Ok(true);
        }
        for n in 0..self.peers.len() {
            let i = (self.cursor + n) % self.peers.len();
            if let Some(p) = &self.peers[i] {
                if p.remote_closed && (p.closing || p.input.is_none()) {
                    let channel = p.channel;
                    if !self
                        .pending
                        .as_ref()
                        .is_some_and(|p| Self::action_channel(&p.action) == Some(channel))
                    {
                        self.finish_peer(i)?;
                        self.cursor = (i + 1) % self.peers.len();
                        return Ok(true);
                    }
                }
                if self.inner(i, now)? {
                    self.cursor = (i + 1) % self.peers.len();
                    return Ok(true);
                }
            }
        }
        if self.cadet.pending_transmit().is_some() {
            return Ok(false);
        }
        for i in 0..self.peers.len() {
            if let Some(p) = &self.peers[i]
                && p.closing
                && !p.remote_closed
            {
                let channel = p.channel;
                let started = Instant::now();
                match self.cadet.destroy(channel) {
                    Ok(transmit) => {
                        self.pending(transmit, Action::Destroy(channel), started)?;
                        return Ok(true);
                    }
                    Err(e) if retry(&e) => {}
                    Err(cadet::Error::Protocol(Fault::Stale | Fault::StaleGeneration)) => {
                        self.finish_peer(i)?;
                        return Ok(true);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        for i in 0..self.ports.len() {
            if self.ports[i].disabled
                && let Some(port) = self.ports[i].port
            {
                if self.cadet.port_hash(port).is_err() {
                    self.ports[i].port = None;
                    return Ok(true);
                }
                let started = Instant::now();
                match self.cadet.close_port(port) {
                    Ok(Some(tx)) => {
                        self.pending(tx, Action::PortClose(i), started)?;
                        return Ok(true);
                    }
                    Ok(None) => {
                        self.ports[i].port = None;
                        return Ok(true);
                    }
                    Err(e) if retry(&e) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        if !self.stopping {
            for i in 0..self.ports.len() {
                if self.ports[i].port.is_none() && !self.ports[i].disabled {
                    let hash = self.ports[i].binding.hash;
                    let started = Instant::now();
                    match self.cadet.listen(hash) {
                        Ok(port) => {
                            self.ports[i].port = Some(port);
                            let tx = self.cadet.pending_transmit().ok_or(Fault::Stale)?;
                            self.pending(tx, Action::PortOpen, started)?;
                            return Ok(true);
                        }
                        Err(e) if retry(&e) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        if self.peer_held.is_none()
            && let Some(out) = self.engine.peer_output()
        {
            let flow = out.flow;
            let write = out.write;
            let expires = out.expires;
            let at = self.until(now, expires, Some(self.limits.io_grace));
            match at {
                Ok(until) => self.peer_held = Some(Held { flow, write, until }),
                Err(e) => {
                    if let Some((_, s)) = &self.source {
                        self.engine.peer_unsent(s, &write, e)?;
                    }
                    return Ok(true);
                }
            }
        }
        if let Some(held) = &self.peer_held {
            let flow = held.flow.clone();
            let write = held.write.clone();
            let Some(i) = self.flow(&flow) else {
                return Err(Fault::Stale.into());
            };
            let p = self.peers[i].as_ref().ok_or(Fault::Stale)?;
            if p.closing || p.remote_closed {
                let held = self.peer_held.take().ok_or(Fault::Stale)?;
                if let Some((_, s)) = &self.source {
                    self.engine.peer_unsent(s, &held.write, Fault::Cancelled)?;
                }
                return Ok(true);
            }
            let channel = p.channel;
            let out = self.engine.peer_output().ok_or(Fault::Stale)?;
            if out.write != write || out.flow != flow {
                return Err(Fault::Stale.into());
            }
            let started = Instant::now();
            match self.cadet.send(channel, 0, out.bytes) {
                Ok(transmit) => {
                    self.peer_held = None;
                    self.pending(transmit, Action::Data { channel, write }, started)?;
                    return Ok(true);
                }
                Err(e) if retry(&e) => {}
                Err(e) => {
                    let fault = match &e {
                        cadet::Error::Protocol(e) => *e,
                        _ => Fault::Io,
                    };
                    let held = self.peer_held.take().ok_or(Fault::Stale)?;
                    if let Some((_, s)) = &self.source {
                        self.engine.peer_unsent(s, &held.write, fault)?;
                    }
                    observe(Event::Refused {
                        channel,
                        error: fault,
                    });
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    fn written(&mut self, w: cadet::Written<'id>) -> Result<(), Error> {
        let Some(p) = self.pending.take() else {
            return Ok(());
        };
        if p.transmit != w.transmit {
            self.pending = Some(p);
            return Err(Fault::Stale.into());
        }
        match p.action {
            Action::Data { write, .. } => {
                let s = &self.source.as_ref().ok_or(Fault::Stale)?.1;
                self.engine.peer_written(s, &write)?;
                self.report.peer_written = self.report.peer_written.saturating_add(1);
            }
            Action::Ack { receipts, .. } => {
                for input in receipts {
                    self.engine.acknowledged(&input)?;
                }
                self.report.receive_done = self.report.receive_done.saturating_add(1);
            }
            Action::Destroy(channel) => {
                if let Some(i) = self.peer(channel) {
                    self.finish_peer(i)?;
                }
            }
            Action::PortClose(i) => self.ports[i].port = None,
            Action::PortOpen | Action::Internal => {}
        }
        Ok(())
    }
    pub(super) fn cadet_event(
        &mut self,
        event: cadet::Step<'id>,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        match event {
            cadet::Step::Connected(epoch) => {
                if self.source.is_some() {
                    return Err(Fault::Conflict.into());
                }
                let source = self.engine.attached()?;
                self.source = Some((epoch, source));
                observe(Event::Connected(epoch));
            }
            cadet::Step::Written(w) => self.written(w)?,
            cadet::Step::Incoming { channel, port } => {
                self.read_hard = None;
                let Some(i) = self.peers.iter().position(Option::is_none) else {
                    let e = self.cadet.reconnect()?;
                    self.cadet_event(e, now, observe)?;
                    return Ok(true);
                };
                let binding = self
                    .ports
                    .iter()
                    .find(|p| p.port == Some(port) && !p.disabled)
                    .map(|p| p.binding);
                let info = self.cadet.channel_info(channel)?;
                let result = if self.stopping {
                    Err(Fault::Closed)
                } else if let Some(binding) = binding {
                    let s = &self.source.as_ref().ok_or(Fault::Stale)?.1;
                    self.engine.accept(s, info.peer, binding.target, now)
                } else {
                    Err(Fault::NotFound)
                };
                let (flow, closing, hard) = match result {
                    Ok(flow) => (Some(flow), false, None),
                    Err(error) => {
                        observe(Event::Refused { channel, error });
                        (None, true, Some(self.hard()?))
                    }
                };
                self.peers[i] = Some(Peer {
                    channel,
                    flow,
                    input: None,
                    closing,
                    remote_closed: false,
                    hard,
                    first: Some(
                        Instant::now()
                            .checked_add(self.limits.first_input)
                            .ok_or(Fault::Overflow)?,
                    ),
                });
                self.report.channels = self.report.channels.saturating_add(1);
            }
            cadet::Step::Data(packet) => {
                self.read_hard = None;
                let channel = packet.channel();
                let i = self.peer(channel).ok_or(Fault::Stale)?;
                if self.peers[i]
                    .as_ref()
                    .is_none_or(|p| p.closing || p.remote_closed)
                {
                    // Local revocation and known physical destruction admit no
                    // new packet, even if a late event was already queued.
                    return Ok(true);
                }
                let mut rest = packet.messages();
                let mut count = 0;
                while !rest.is_empty() {
                    let (_, tail) = Frame::decode_prefix(rest)?;
                    rest = tail;
                    count += 1;
                    if count > self.limits.inner_frames {
                        self.closing(i)?;
                        observe(Event::Refused {
                            channel,
                            error: Fault::Capacity,
                        });
                        return Ok(true);
                    }
                }
                let mut receipts = Vec::new();
                receipts
                    .try_reserve_exact(count)
                    .map_err(|_| Fault::Capacity)?;
                let lifetime = self.engine.input_lifetime();
                let expires = MonoInstant(now.0.checked_add(lifetime).ok_or(Fault::Overflow)?);
                let until = Instant::now()
                    .checked_add(Duration::from_micros(lifetime))
                    .ok_or(Fault::Overflow)?;
                let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                if p.input.is_some() {
                    return Err(Fault::Conflict.into());
                }
                p.input = Some(Outer {
                    packet,
                    expires,
                    until,
                    at: 0,
                    next: 0,
                    pending: None,
                    ready: false,
                    receipts,
                });
            }
            cadet::Step::Destroyed(channel) => {
                self.read_hard = None;
                if let Some(i) = self.peer(channel) {
                    let hard = self.hard()?;
                    let flow = self.peers[i].as_ref().ok_or(Fault::Stale)?.flow.clone();
                    if let Some(flow) = flow {
                        // peer_held has never entered cadet.send. The distinct
                        // pending native action is never selected as unadmitted.
                        let unadmitted = self
                            .peer_held
                            .as_ref()
                            .filter(|held| held.flow == flow)
                            .map(|held| held.write.clone());
                        self.engine.peer_ended(&flow, unadmitted.as_ref())?;
                        if unadmitted.is_some() {
                            self.peer_held = None;
                        }
                    }
                    let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                    p.remote_closed = true;
                    let hard = p.input.as_ref().map_or(hard, |outer| hard.min(outer.until));
                    p.hard = Some(p.hard.map_or(hard, |original| original.min(hard)));
                }
            }
            cadet::Step::Lost { report, cause, .. } => {
                self.pending = None;
                self.peer_held = None;
                self.read_hard = None;
                if let Some((epoch, source)) = self.source.take() {
                    if epoch != report.epoch {
                        return Err(Fault::Stale.into());
                    }
                    self.engine.source_lost(&source)?;
                }
                for p in &mut self.peers {
                    *p = None;
                }
                observe(Event::CadetLost { report, cause });
            }
            cadet::Step::ConnectRetry { error, retry_after } => {
                observe(Event::ConnectRetry { error, retry_after })
            }
            cadet::Step::Unavailable(e) => return Err(e.into()),
            cadet::Step::Blocked { .. } => {
                let hard = self.hard()?;
                self.read_hard.get_or_insert(hard);
                return Ok(false);
            }
            cadet::Step::Activity { read_bytes, .. } => {
                if read_bytes > 0 {
                    let hard = self.hard()?;
                    self.read_hard.get_or_insert(hard);
                }
            }
            cadet::Step::Credit { .. }
            | cadet::Step::Ignored { .. }
            | cadet::Step::RejectedIncoming { .. } => self.read_hard = None,
            cadet::Step::WaitDeadline => return Ok(false),
            cadet::Step::Closed => return Ok(false),
        }
        Ok(true)
    }
    pub(super) fn poll_cadet(
        &mut self,
        cx: &mut Context<'_>,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.stopping && self.source.is_none() {
            return Poll::Pending;
        }
        let started = Instant::now();
        let result = self.cadet.poll(cx, None);
        if self.pending.is_none()
            && let Some(tx) = self.cadet.pending_transmit()
        {
            self.pending(tx, Action::Internal, started)?;
        }
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(e)) => {
                if self.cadet_event(e, now, observe)? {
                    Poll::Ready(Ok(Progress::Activity))
                } else {
                    Poll::Pending
                }
            }
        }
    }
    pub(super) fn close_cadet(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let result = self.cadet.close();
        self.pending = None;
        self.peer_held = None;
        self.read_hard = None;
        let mut failure = None;
        if let Some((_, source)) = self.source.take()
            && let Err(e) = self.engine.source_lost(&source)
        {
            failure = Some(e.into());
        }
        for p in &mut self.peers {
            *p = None;
        }
        match result {
            Ok(Some(report)) => observe(Event::CadetLost {
                report,
                cause: cadet::LossCause::Requested,
            }),
            Ok(None) => {}
            Err(e) => {
                if failure.is_none() {
                    failure = Some(e.into())
                }
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
