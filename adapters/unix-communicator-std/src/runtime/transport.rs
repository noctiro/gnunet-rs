//! Registration, framed IO and retirement of one original TRANSPORT MQ.
use super::{
    Epoch, Event, Fault, Protocol, Queue, Role, Runtime, Send, SendOutcome, bytes, encode,
};
use crate::native::Address;
use gnunet_client_host::channel::ConnectionStep;
use gnunet_service_runtime::framing::ReadStep;
use gnunet_wire::official::communicator::{Characteristics, Request, Response};
use std::{
    io,
    task::{Context, Poll},
};
use zeroize::Zeroizing;

fn transport_io(error: &io::Error) -> bool {
    if gnunet_client_host::resolution::PortError::from_io(error).is_some() {
        return false;
    }
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::WriteZero
    )
}

impl<'id> Runtime<'id> {
    pub(super) fn retire_transport(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> (usize, usize, usize, usize) {
        let outputs = self.outputs.len();
        let exposed = self.outputs.iter().filter(|o| o.bytes != 0).count();
        let incoming = self.debts.iter().flatten().count();
        let mut sends = 0;
        for output in &self.outputs {
            observe(Event::OutputRetired {
                write: output.id,
                bytes: output.bytes,
            });
        }
        for debt in self.debts.iter_mut().filter_map(Option::take) {
            observe(Event::IncomingRetired {
                epoch: self.epoch,
                flow_id: debt.flow,
                peer: debt.peer,
                written: debt.written,
            });
        }
        for slot in &mut self.queues {
            let Some(queue) = slot.as_mut() else {
                continue;
            };
            let failed = queue.failed_send();
            if queue.retire_send(self.epoch, self.socket_epoch, observe) {
                sends += 1;
                // poll_send is one atomic nonblocking syscall: Pending owns no
                // in-flight native write. This cancels only the original intent;
                // actual Whole/Failed/Unknown facts remain separate below.
            }
            // A failed native destination is not live metadata to reannounce
            // after MQ replacement, even if its original DOWN was not written.
            if failed {
                *slot = None;
                self.statistics.queues -= 1;
                continue;
            }
            queue.granted = false;
            queue.announced = false;
        }
        if let Some(input) = self.input.take() {
            observe(Event::InputRetired {
                epoch: self.epoch,
                socket: self.socket_epoch,
                bytes: input.packet.len(),
            });
        }
        self.statistics.transport_failures = self
            .statistics
            .transport_failures
            .saturating_add(incoming as u64);
        self.outputs.clear();
        self.rx = None;
        self.epoch = None;
        self.registered = false;
        self.address_written = false;
        self.started = false;
        self.restoring = false;
        self.restore_fence = 0;
        self.whole_write = 0;
        (outputs, exposed, incoming, sends)
    }
    fn transport_lost(
        &mut self,
        cause: Option<io::Error>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Fault> {
        let epoch = self.epoch.ok_or(Protocol::Stale)?;
        let (input_bytes, held_input) = self.transport.framing().map_or((0, false), |f| {
            (f.read_progress_bytes(), f.frame().is_some())
        });
        // Physical retirement precedes all callback/original-byte retirement.
        // Native socket, identity, clock, queue addresses/idle and parent bounds
        // are untouched. Channel retains its original source and retry owner.
        self.transport.detach();
        let (outputs, exposed, incoming, sends) = self.retire_transport(observe);
        let retry_after = self.transport.schedule_retry()?;
        observe(Event::TransportLost {
            epoch,
            cause,
            input_bytes,
            held_input,
            outputs,
            exposed,
            incoming,
            sends,
            retry_after,
        });
        Ok(())
    }
    pub(super) fn poll_connect(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Fault>> {
        if self.epoch.is_some() {
            return Poll::Pending;
        }
        // Recheck inside CLIENT after configuration, timers and resolution;
        // an outer scheduler observation cannot bound those providers.
        self.transport_gate.set(self.work_bound())?;
        match self.transport.poll_connect(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(ConnectionStep::Attached)) => {
                let serial = self.next_epoch.checked_add(1).ok_or(Protocol::Overflow)?;
                let epoch = Epoch {
                    scope: self.scope,
                    serial,
                };
                self.next_epoch = serial;
                self.epoch = Some(epoch);
                self.restoring = true;
                self.restore_fence = 0;
                self.whole_write = 0;
                observe(Event::Attached(epoch));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                observe(Event::ConnectRetry(error));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => Poll::Ready(Err(e.into())),
        }
    }
    pub(super) fn setup(
        &mut self,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        if !self.started && self.epoch.is_some() && self.identity.peer().is_some() {
            let a = encode(Request::Register {
                characteristics: Characteristics::Reliable,
                can_burst: false,
                prefix: b"unix",
            })?;
            let address = self.next_address.checked_add(1).ok_or(Protocol::Overflow)?;
            let b = encode(Request::AddAddress {
                id: address,
                validity: u64::MAX,
                network: 1,
                address: &self.uri,
            })?;
            let bound = self.operation(now)?;
            self.enqueue(a, Role::Register, bound, observe)?;
            self.enqueue(b, Role::Address, bound, observe)?;
            self.next_address = address;
            self.started = true;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Fault>> {
        if self.outputs.is_empty() {
            return Poll::Pending;
        }
        match self
            .transport
            .framing_mut()
            .ok_or(Protocol::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if transport_io(&e) => {
                self.transport_lost(Some(e), observe)?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(w)) => {
                let out = self.outputs.front_mut().ok_or(Protocol::Stale)?;
                if out.id != w.origin {
                    return Poll::Ready(Err(Protocol::Stale.into()));
                }
                out.bytes = out.bytes.checked_add(w.bytes).ok_or(Protocol::Overflow)?;
                if let Role::SendResult(id) = out.role {
                    let send = self
                        .queues
                        .iter_mut()
                        .flatten()
                        .find(|q| q.id == id)
                        .and_then(|q| q.send.as_mut())
                        .ok_or(Protocol::Stale)?;
                    send.ack_bytes = send
                        .ack_bytes
                        .checked_add(w.bytes)
                        .ok_or(Protocol::Overflow)?;
                    if w.complete {
                        send.ack_written = true;
                    }
                }
                observe(Event::Written {
                    write: w.origin,
                    bytes: w.bytes,
                    complete: w.complete,
                });
                if w.complete {
                    let out = self.outputs.pop_front().ok_or(Protocol::Stale)?;
                    self.whole_write = out.id.serial;
                    match out.role {
                        Role::Register => self.registered = true,
                        Role::Address => {
                            self.address_written = true;
                            if self.registered {
                                self.ever_ready = true;
                                self.transport.reset_backoff();
                            }
                        }
                        Role::QueueSetup(id) => {
                            let q = self
                                .queues
                                .iter_mut()
                                .flatten()
                                .find(|q| q.id == id)
                                .ok_or(Protocol::Stale)?;
                            if Some(q.source) != self.epoch.map(|epoch| epoch.serial) {
                                return Poll::Ready(Err(Protocol::Stale.into()));
                            }
                            if q.send.is_some() || q.announced {
                                return Poll::Ready(Err(Protocol::Conflict.into()));
                            }
                            q.announced = true;
                            q.granted = true;
                        }
                        Role::Incoming(flow) => {
                            let debt = self
                                .debts
                                .iter_mut()
                                .flatten()
                                .find(|d| d.flow == flow)
                                .ok_or(Protocol::Stale)?;
                            debt.written = true;
                            self.statistics.incoming_written =
                                self.statistics.incoming_written.saturating_add(1)
                        }
                        Role::SendAck(id) => {
                            let q = self
                                .queues
                                .iter_mut()
                                .flatten()
                                .find(|q| q.id == id)
                                .ok_or(Protocol::Stale)?;
                            q.send = None;
                            q.granted = true
                        }
                        Role::SendDown(id) => {
                            let index = self
                                .queues
                                .iter()
                                .position(|q| q.as_ref().is_some_and(|q| q.id == id))
                                .ok_or(Protocol::Stale)?;
                            let q = self.queues[index].as_mut().ok_or(Protocol::Stale)?;
                            if !q.failed_send() {
                                return Poll::Ready(Err(Protocol::Conflict.into()));
                            }
                            q.retire_send(self.epoch, self.socket_epoch, observe);
                            self.queues[index] = None;
                            self.statistics.queues -= 1;
                        }
                        Role::Control | Role::QueueDown | Role::SendResult(_) => {}
                    }
                }
                Poll::Ready(Ok(()))
            }
        }
    }
    pub(super) fn dispatch(
        &mut self,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        if !self.registered {
            return Ok(false);
        }
        // A held complete RX remains on this original MQ while capacity-bound;
        // writes and existing callbacks continue to drain independently.
        let f = self.transport.framing().ok_or(Protocol::NotReady)?;
        let Some(frame) = f.frame() else {
            return Ok(false);
        };
        let response = Response::decode(frame)?;
        if !matches!(response, Response::Received(..)) && !self.room(3, 131070) {
            return Ok(false);
        }
        match response {
            Response::Create(request, peer, address) => {
                let request_id = request;
                let remote_peer = peer;
                let existing = gnunet_unix_communicator::Address::decode(address)
                    .and_then(|v| Address::new(v.path()).map_err(|_| Protocol::InvalidInput));
                let found = existing.as_ref().ok().and_then(|a| {
                    self.queues.iter().position(|q| {
                        q.as_ref()
                            .is_some_and(|q| q.peer == remote_peer && q.address == *a)
                    })
                });
                if found.is_some_and(|index| {
                    self.queues[index].as_ref().is_some_and(Queue::failed_send)
                }) {
                    // Keep this actual CREATE and its original RX deadline
                    // until ACK/DOWN drains. It must not revive the old QID.
                    return Ok(false);
                }
                let room = self.queues.iter().any(Option::is_none);
                // Address is already owned before releasing the frame. No false
                // connection existence/authentication follows from local create.
                self.transport
                    .framing_mut()
                    .ok_or(Protocol::NotReady)?
                    .release_frame();
                self.rx = None;
                let accepted = if let Some(index) = found {
                    if self.queues[index].as_ref().ok_or(Protocol::Stale)?.source
                        != self.epoch.ok_or(Protocol::NotReady)?.serial
                    {
                        self.announce_queue(index, now, observe)?;
                    }
                    true
                } else if room {
                    match existing {
                        Ok(a) => {
                            self.queue_new(a, remote_peer, false, now, observe)?;
                            true
                        }
                        Err(_) => false,
                    }
                } else {
                    false
                };
                self.enqueue(
                    encode(Request::Created(request_id, accepted))?,
                    Role::Control,
                    self.operation(now)?,
                    observe,
                )?;
                return Ok(true);
            }
            Response::Send(id, message_id, peer, message) => {
                let Some(index) = self.queues.iter().position(|q| {
                    q.as_ref().is_some_and(|q| {
                        q.id == id
                            && q.peer == peer
                            && q.announced
                            && !q.failed_send()
                            && Some(q.source) == self.epoch.map(|epoch| epoch.serial)
                    })
                }) else {
                    // A SEND may already be in flight when its original queue
                    // expires. Official API reports GNUNET_NO, without inventing
                    // a network write or binding this id to a new address.
                    let rejected = encode(Request::Sent {
                        message_id,
                        queue: id,
                        peer,
                        status: 0,
                    })?;
                    let bound = self.rx.unwrap_or(self.operation(now)?);
                    self.transport
                        .framing_mut()
                        .ok_or(Protocol::NotReady)?
                        .release_frame();
                    self.rx = None;
                    self.enqueue(rejected, Role::Control, bound, observe)?;
                    return Ok(true);
                };
                let q = self.queues[index].as_ref().ok_or(Protocol::Stale)?;
                if !q.granted || q.send.is_some() || message.len() > self.mtu {
                    return Err(Protocol::Malformed.into());
                }
                let mut packet = Zeroizing::new(bytes(gnunet_unix_communicator::encoded_len(
                    message, self.mtu,
                )?)?);
                gnunet_unix_communicator::encode(
                    self.identity.peer().ok_or(Protocol::NotReady)?,
                    message,
                    self.mtu,
                    &mut packet,
                )?;
                let send = Send {
                    outcome: SendOutcome::Unsent,
                    ack_bytes: 0,
                    ack_written: false,
                    message: message_id,
                    packet,
                    bound: self.operation(now)?,
                    retry: None,
                    status: None,
                };
                let q = self.queues[index].as_mut().ok_or(Protocol::Stale)?;
                q.send = Some(send);
                q.granted = false;
            }
            Response::Received(flow, peer) => {
                let index = self
                    .debts
                    .iter()
                    .position(|d| {
                        d.as_ref()
                            .is_some_and(|d| d.flow == flow && d.peer == peer && d.written)
                    })
                    .ok_or(Protocol::Stale)?;
                self.debts[index] = None;
                self.statistics.incoming_callbacks =
                    self.statistics.incoming_callbacks.saturating_add(1);
                observe(Event::Received {
                    epoch: self.epoch.ok_or(Protocol::NotReady)?,
                    flow_id: flow,
                    peer,
                });
            }
            Response::Backchannel(..) | Response::Burst(..) | Response::Unknown(_) => {
                observe(Event::UnsupportedCommand);
            }
        }
        self.transport
            .framing_mut()
            .ok_or(Protocol::NotReady)?
            .release_frame();
        self.rx = None;
        Ok(true)
    }
    pub(super) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Fault>> {
        if self.epoch.is_none() || !self.registered {
            return Poll::Pending;
        }
        let f = self.transport.framing_mut().ok_or(Protocol::NotReady)?;
        if f.frame().is_some() {
            return Poll::Pending;
        }
        match f.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if transport_io(&e) => {
                self.transport_lost(Some(e), observe)?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                self.transport_lost(None, observe)?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                if bytes != 0 && self.rx.is_none() {
                    self.rx = Some(self.operation(now)?);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}
