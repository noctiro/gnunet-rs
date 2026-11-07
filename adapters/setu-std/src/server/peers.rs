//! Real CADET port/channel/immutable write ownership on one original MQ.
use super::*;
impl<'id, 'slots> Server<'id, 'slots> {
    pub(super) fn effect(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        let Some(effect) = self.core.next_effect() else {
            return Ok(false);
        };
        match effect {
            Effect::Listen { client, app } => {
                if let Some(index) = self.ports.iter().position(Option::is_none) {
                    self.ports[index] = Some(Bound {
                        client,
                        app,
                        port: None,
                        ready: false,
                        closing: false,
                        hard: None,
                    });
                } else {
                    self.core.listener_ready(&client, Err(Fault::Capacity))?;
                    observe(Event::Refused {
                        operation: None,
                        error: Fault::Capacity,
                    });
                }
            }
            Effect::Unlisten { client, .. } => {
                if let Some(index) = self
                    .ports
                    .iter()
                    .position(|p| p.as_ref().is_some_and(|p| p.client == client))
                {
                    let hard = self.hard()?;
                    let p = self.ports[index].as_mut().ok_or(Fault::Stale)?;
                    p.closing = true;
                    p.hard.get_or_insert(hard);
                } else {
                    self.core.listener_closed(&client)?;
                }
            }
            Effect::Open {
                operation,
                peer,
                app,
            } => {
                if let Some(index) = self.opens.iter().position(Option::is_none) {
                    self.opens[index] = Some(Opening {
                        operation,
                        peer,
                        app,
                    });
                } else {
                    self.core.connect_failed(&operation, Fault::Capacity)?;
                    observe(Event::Refused {
                        operation: Some(operation),
                        error: Fault::Capacity,
                    });
                }
            }
            Effect::Send {
                operation,
                transmission,
                bytes,
            } => {
                let owned = OwnedFrame::copy_from(bytes)?;
                if let Some(index) = self.op_index(&operation) {
                    let p = self.peers[index].as_mut().ok_or(Fault::Stale)?;
                    if p.send.is_some() {
                        return Err(Fault::Conflict.into());
                    }
                    p.send = Some((transmission, owned));
                } else {
                    self.core.abort(&operation, Fault::NotReady)?;
                }
            }
            Effect::Close { operation } => {
                if let Some(index) = self.op_index(&operation) {
                    self.mark_close(index)?;
                } else if let Some(index) = self
                    .opens
                    .iter()
                    .position(|o| o.as_ref().is_some_and(|o| o.operation == operation))
                {
                    self.opens[index] = None;
                    self.core.retired(&operation)?;
                } else {
                    self.core.retired(&operation)?;
                }
            }
            Effect::CloseClient { client, error } => {
                if let Some(index) = self
                    .apps
                    .iter()
                    .position(|a| a.as_ref().is_some_and(|a| a.client == client))
                {
                    self.stop_app(index, CloseCause::Fault(error.into()), observe)?;
                }
            }
        }
        Ok(true)
    }
    fn pending(
        &mut self,
        transmit: cadet::Transmit<'id>,
        action: Action<'id>,
        started: Instant,
    ) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Fault::Conflict.into());
        }
        let hard = started
            .checked_add(self.limits.retirement_grace)
            .ok_or(Fault::Overflow)?;
        self.pending = Some(Pending {
            transmit,
            action,
            hard,
        });
        Ok(())
    }
    pub(super) fn retire_closed_ports(&mut self) -> Result<bool, Error> {
        for i in 0..self.ports.len() {
            let Some(p) = &self.ports[i] else { continue };
            if !p.closing {
                continue;
            }
            if p.port.is_none() {
                let p = self.ports[i].take().ok_or(Fault::Stale)?;
                self.core.listener_closed(&p.client)?;
                return Ok(true);
            }
            let port = p.port.ok_or(Fault::Stale)?;
            if self.cadet.port_hash(port).is_err() {
                let p = self.ports[i].take().ok_or(Fault::Stale)?;
                self.core.listener_closed(&p.client)?;
                return Ok(true);
            }
            if self.cadet.pending_transmit().is_some() {
                continue;
            }
            let started = Instant::now();
            match self.cadet.close_port(port) {
                Ok(Some(transmit)) => {
                    self.pending(transmit, Action::PortClose(port), started)?;
                    return Ok(true);
                }
                Ok(None) => {
                    let p = self.ports[i].take().ok_or(Fault::Stale)?;
                    self.core.listener_closed(&p.client)?;
                    return Ok(true);
                }
                Err(e) if retry(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(false)
    }
    fn reconcile_ports(&mut self) -> Result<bool, Error> {
        for i in 0..self.ports.len() {
            let Some(p) = &self.ports[i] else { continue };
            if p.closing || p.ready {
                continue;
            }
            if let Some(port) = p.port
                && self.cadet.port_announced(port).unwrap_or(false)
            {
                let p = self.ports[i].as_mut().ok_or(Fault::Stale)?;
                p.ready = true;
                match self.core.listener_ready(&p.client, Ok(())) {
                    Ok(()) => {}
                    Err(Fault::Cancelled) => {
                        p.closing = true;
                        p.hard = Some(
                            Instant::now()
                                .checked_add(self.limits.retirement_grace)
                                .ok_or(Fault::Overflow)?,
                        );
                    }
                    Err(e) => return Err(e.into()),
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn input(&mut self, index: usize, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        let Some(peer) = &self.peers[index] else {
            return Ok(false);
        };
        if peer.closing && !peer.remote_closed {
            return Ok(false);
        }
        let Some(input) = &peer.input else {
            return Ok(false);
        };
        // A fully received packet still belongs to the original operation when
        // a later Destroyed event retires its native channel. Do not announce a
        // new incoming operation after its source has already gone.
        if peer.remote_closed && peer.operation.is_none() {
            self.peers[index].as_mut().ok_or(Fault::Stale)?.input = None;
            return Ok(true);
        }
        let messages = input.packet.messages();
        if input.at == messages.len() {
            if peer.remote_closed {
                // The real channel is gone: release only the local packet. Its
                // old Delivery is no longer eligible for receive_done/ACK.
                self.peers[index].as_mut().ok_or(Fault::Stale)?.input = None;
                return Ok(true);
            }
            if self.cadet.pending_transmit().is_some() {
                return Ok(false);
            }
            let delivery = input.packet.delivery();
            let channel = peer.channel;
            let started = Instant::now();
            return match self.cadet.receive_done(delivery) {
                Ok(transmit) => {
                    self.peers[index].as_mut().ok_or(Fault::Stale)?.input = None;
                    self.pending(transmit, Action::Ack(channel), started)?;
                    Ok(true)
                }
                Err(e) if retry(&e) => Ok(false),
                Err(e) => Err(e.into()),
            };
        }
        let tail = messages.get(input.at..).ok_or(Fault::Malformed)?;
        let header = MessageHeader::decode(tail)?;
        let n = header.size();
        let Some(frame) = tail.get(..n) else {
            self.reject_input(index, Fault::Truncated, observe)?;
            return Ok(true);
        };
        let operation = peer.operation.clone();
        let result = if let Some(operation) = operation {
            self.core
                .receive(&operation, frame, &mut self.codec)
                .map(|()| None)
        } else {
            let listener = peer.listener.as_ref().ok_or(Fault::Stale)?.clone();
            let info = self.cadet.channel_info(peer.channel)?;
            let now = self.now()?;
            let expires = peer.expires;
            self.core
                .incoming(&listener, info.peer, frame, now, expires)
                .map(Some)
        };
        match result {
            Ok(operation) => {
                let p = self.peers[index].as_mut().ok_or(Fault::Stale)?;
                if let Some(operation) = operation {
                    p.operation = Some(operation);
                    p.listener = None;
                }
                p.input.as_mut().ok_or(Fault::Stale)?.at += n;
                Ok(true)
            }
            Err(Fault::WouldBlock) => Ok(false),
            Err(e) => {
                self.reject_input(index, e, observe)?;
                Ok(true)
            }
        }
    }
    fn reject_input(
        &mut self,
        index: usize,
        error: Fault,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let operation = self.peers[index]
            .as_ref()
            .ok_or(Fault::Stale)?
            .operation
            .clone();
        if let Some(op) = &operation {
            self.core.abort(op, error)?;
        }
        observe(Event::Refused { operation, error });
        // Rejected/cancelled input is abandoned, never credited as processed.
        // In particular, a remotely closed channel must not retry it forever.
        self.peers[index].as_mut().ok_or(Fault::Stale)?.input = None;
        self.mark_close(index)
    }
    pub(super) fn peer_work(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        if self.reconcile_ports()? || self.retire_closed_ports()? {
            return Ok(true);
        }
        for n in 0..self.peers.len() {
            let i = (self.peer_cursor + n) % self.peers.len();
            if self.peers[i].is_some() {
                let remote = self.peers[i].as_ref().is_some_and(|p| p.remote_closed);
                if remote {
                    // Process only already-owned bytes before the terminal
                    // callback. Other MQ events/credits may still make progress;
                    // no new input or peer send is admitted on this gone channel.
                    if self.input(i, observe)? {
                        self.peer_cursor = (i + 1) % self.peers.len();
                        return Ok(true);
                    }
                    if self.peers[i].as_ref().is_some_and(|p| p.input.is_some()) {
                        continue;
                    }
                    let channel = self.peers[i].as_ref().ok_or(Fault::Stale)?.channel;
                    if !self
                        .pending
                        .as_ref()
                        .is_some_and(|p| Self::action_channel(&p.action) == Some(channel))
                    {
                        self.finish_peer(i)?;
                        self.peer_cursor = (i + 1) % self.peers.len();
                        return Ok(true);
                    }
                    continue;
                }
                if self.input(i, observe)? {
                    self.peer_cursor = (i + 1) % self.peers.len();
                    return Ok(true);
                }
            }
        }
        if self.cadet.pending_transmit().is_some() {
            return Ok(false);
        }
        for i in 0..self.peers.len() {
            let Some(peer) = &self.peers[i] else { continue };
            let channel = peer.channel;
            if peer.closing {
                let started = Instant::now();
                match self.cadet.destroy(channel) {
                    Ok(transmit) => {
                        self.pending(transmit, Action::Destroy(channel), started)?;
                        return Ok(true);
                    }
                    Err(e) if retry(&e) => {}
                    Err(cadet::Error::Protocol(Fault::StaleGeneration | Fault::Stale)) => {
                        self.finish_peer(i)?;
                        return Ok(true);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        for i in 0..self.ports.len() {
            let Some(port) = &self.ports[i] else { continue };
            if port.port.is_none() && !port.closing {
                let hash = port.app;
                let started = Instant::now();
                match self.cadet.listen(hash) {
                    Ok(port) => {
                        self.ports[i].as_mut().ok_or(Fault::Stale)?.port = Some(port);
                        let tx = self.cadet.pending_transmit().ok_or(Fault::Stale)?;
                        self.pending(tx, Action::PortOpen(port), started)?;
                        return Ok(true);
                    }
                    Err(e) if retry(&e) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        if let Some(i) = self.opens.iter().position(Option::is_some) {
            let open = self.opens[i].as_ref().ok_or(Fault::Stale)?;
            let Some(slot) = self.peers.iter().position(Option::is_none) else {
                return Ok(false);
            };
            let started = Instant::now();
            match self.cadet.open(open.peer, open.app) {
                Ok(channel) => {
                    let open = self.opens[i].take().ok_or(Fault::Stale)?;
                    self.peers[slot] = Some(Peer {
                        channel,
                        operation: Some(open.operation),
                        listener: None,
                        expires: 0,
                        opening: true,
                        closing: false,
                        remote_closed: false,
                        hard: None,
                        send: None,
                        input: None,
                    });
                    let tx = self.cadet.pending_transmit().ok_or(Fault::Stale)?;
                    self.pending(tx, Action::Open(channel), started)?;
                    return Ok(true);
                }
                Err(e) if retry(&e) => {}
                Err(e) => {
                    let open = self.opens[i].take().ok_or(Fault::Stale)?;
                    self.core.connect_failed(&open.operation, Fault::Io)?;
                    return Err(e.into());
                }
            }
        }
        for n in 0..self.peers.len() {
            let i = (self.peer_cursor + n) % self.peers.len();
            let Some(peer) = &self.peers[i] else { continue };
            if peer.closing || peer.opening {
                continue;
            }
            if let Some((transmission, bytes)) = &peer.send {
                let transmission = transmission.clone();
                let channel = peer.channel;
                let operation = peer.operation.as_ref().ok_or(Fault::Stale)?.clone();
                let started = Instant::now();
                match self.cadet.send(channel, 0, bytes.bytes()) {
                    Ok(transmit) => {
                        self.peers[i].as_mut().ok_or(Fault::Stale)?.send = None;
                        self.pending(
                            transmit,
                            Action::Send {
                                channel,
                                operation,
                                transmission,
                            },
                            started,
                        )?;
                        self.peer_cursor = (i + 1) % self.peers.len();
                        return Ok(true);
                    }
                    Err(cadet::Error::Protocol(Fault::WouldBlock | Fault::NotReady)) => {}
                    Err(e) => {
                        let reason = match &e {
                            cadet::Error::Protocol(reason) => *reason,
                            _ => Fault::Io,
                        };
                        self.core.abort(&operation, reason)?;
                        self.mark_close(i)?;
                        observe(Event::Refused {
                            operation: Some(operation),
                            error: reason,
                        });
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
    fn action_channel(action: &Action<'id>) -> Option<cadet::Channel<'id>> {
        match action {
            Action::Open(c)
            | Action::Destroy(c)
            | Action::Ack(c)
            | Action::Send { channel: c, .. } => Some(*c),
            _ => None,
        }
    }
    fn written(&mut self, written: cadet::Written<'id>) -> Result<(), Error> {
        let Some(pending) = self.pending.take() else {
            self.reconcile_ports()?;
            return Ok(());
        };
        if pending.transmit != written.transmit {
            self.pending = Some(pending);
            return Err(Fault::Stale.into());
        }
        match pending.action {
            Action::Open(channel) => {
                if let Some(i) = self.peer_index(channel) {
                    let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                    p.opening = false;
                    if !p.closing {
                        let info = self.cadet.channel_info(channel)?;
                        let operation = p.operation.as_ref().ok_or(Fault::Stale)?;
                        if let Err(e) = self.core.connected(operation, info.peer)
                            && e != Fault::Stale
                        {
                            self.mark_close(i)?;
                        }
                    }
                }
            }
            Action::Send {
                operation,
                transmission,
                ..
            } => {
                match self.core.sent(&operation, &transmission) {
                    Ok(()) => {}
                    Err(Fault::Stale) => {}
                    Err(e) => return Err(e.into()),
                }
                self.report.peer_frames = self.report.peer_frames.saturating_add(1);
            }
            Action::Destroy(channel) => {
                if let Some(i) = self.peer_index(channel) {
                    self.finish_peer(i)?;
                }
            }
            Action::PortClose(port) => {
                if let Some(i) = self
                    .ports
                    .iter()
                    .position(|p| p.as_ref().is_some_and(|p| p.port == Some(port)))
                {
                    let p = self.ports[i].take().ok_or(Fault::Stale)?;
                    self.core.listener_closed(&p.client)?;
                }
            }
            Action::Ack(_) => self.report.receive_done = self.report.receive_done.saturating_add(1),
            Action::PortOpen(port) => {
                let _same = self.cadet.port_announced(port)?;
            }
            Action::Internal => {}
        }
        self.reconcile_ports()?;
        Ok(())
    }
    pub(super) fn native_event(
        &mut self,
        event: cadet::Step<'id>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        match event {
            cadet::Step::Written(w) => self.written(w)?,
            cadet::Step::Incoming { channel, port } => {
                self.read_hard = None;
                let Some(slot) = self.peers.iter().position(Option::is_none) else {
                    let lost = self.cadet.reconnect()?;
                    self.native_event(lost, observe)?;
                    return Ok(true);
                };
                let listener = self
                    .ports
                    .iter()
                    .flatten()
                    .find(|p| p.port == Some(port) && !p.closing)
                    .map(|p| p.client.clone());
                let now = self.now()?;
                let expires = self.expires(now)?;
                let closing = listener.is_none();
                let hard = if closing { Some(self.hard()?) } else { None };
                self.peers[slot] = Some(Peer {
                    channel,
                    operation: None,
                    listener,
                    expires,
                    opening: false,
                    closing,
                    remote_closed: false,
                    hard,
                    send: None,
                    input: None,
                });
            }
            cadet::Step::Data(packet) => {
                self.read_hard = None;
                let channel = packet.channel();
                if let Some(i) = self.peer_index(channel) {
                    let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                    if p.input.is_some() {
                        return Err(Fault::Conflict.into());
                    }
                    p.input = Some(Input { packet, at: 0 });
                } else {
                    return Err(Fault::Stale.into());
                }
            }
            cadet::Step::Destroyed(channel) => {
                self.read_hard = None;
                if let Some(i) = self.peer_index(channel) {
                    let hard = self.hard()?;
                    let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                    p.remote_closed = true;
                    p.closing = true;
                    p.send = None;
                    // Preserve earlier complete DATA for the original operation.
                    // The old channel stays physically gone and cannot send/ACK.
                    p.hard.get_or_insert(hard);
                }
            }
            cadet::Step::Lost { report, cause, .. } => {
                self.pending = None;
                self.read_hard = None;
                // The CADET client detached the physical stream before this
                // event. Original pending payloads are never rebound/replayed.
                for i in 0..self.peers.len() {
                    if self.peers[i].is_some() {
                        self.finish_peer(i)?;
                    }
                }
                self.report.cadet_losses = self.report.cadet_losses.saturating_add(1);
                observe(Event::CadetLost { report, cause });
                self.retire_closed_ports()?;
            }
            cadet::Step::ConnectRetry { error, retry_after } => {
                observe(Event::CadetRetry { error, retry_after })
            }
            cadet::Step::Unavailable(e) => return Err(e.into()),
            cadet::Step::Blocked { .. } => {
                let hard = self.hard()?;
                self.read_hard.get_or_insert(hard);
                return Ok(false);
            }
            cadet::Step::WaitDeadline => return Ok(false),
            cadet::Step::Closed => return Err(Fault::Closed.into()),
            cadet::Step::Connected(_) => {}
            cadet::Step::Credit { .. }
            | cadet::Step::RejectedIncoming { .. }
            | cadet::Step::Ignored { .. } => {
                self.read_hard = None;
            }
            cadet::Step::Activity { read_bytes, .. } => {
                if read_bytes > 0 {
                    let hard = self.hard()?;
                    self.read_hard.get_or_insert(hard);
                }
            }
        }
        Ok(true)
    }
    pub(super) fn poll_cadet(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let started = Instant::now();
        let result = self.cadet.poll(cx, None);
        // Automatic port restoration/rejection also owns one original immutable
        // MQ frame. Give it the same finite physical drain budget, no thread.
        if self.pending.is_none()
            && let Some(transmit) = self.cadet.pending_transmit()
        {
            self.pending(transmit, Action::Internal, started)?;
        }
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
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
