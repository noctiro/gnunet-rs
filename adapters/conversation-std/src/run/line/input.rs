use super::{Call, Completion, Error, Fault, LocalEvent, State};
use gnunet_conversation::{RequestOutcome, wire::Message};
use gnunet_service_runtime::framing::{ReadStep, WriteProgress};
use gnunet_wire::official::{Frame, MessageHeader};
use std::task::{Context, Poll};
impl<'s, 'p, 'c, 'slots> State<'s, 'p, 'c, 'slots> {
    pub(super) fn client_read(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        self.guard(cx)?;
        if self.io.frame().is_some() {
            if self.session.core().is_none() {
                return Ok(false);
            }
            let now = self.now()?;
            let utc = self.utc()?;
            let current = self.selected()?;
            let bytes = self.io.frame().ok_or(Fault::Conflict)?;
            let header = MessageHeader::decode(bytes)?;
            if self.tolerant && !(730..=745).contains(&header.message_type().value()) {
                if !self.io.release_frame() {
                    return Err(Fault::Conflict.into());
                }
                self.client_input = None;
                return Ok(true);
            }
            let message = Message::decode(bytes)?;
            if let Message::Audio { data, .. } = &message {
                let peer_size = Message::PeerAudio(data).encoded_len()?;
                if peer_size > self.limits.core.frame_bytes.min(64348)
                    || peer_size > self.limits.cadet.max_payload_bytes
                {
                    return Err(Fault::TooLarge.into());
                }
            }
            let registering = matches!(&message, Message::Register { .. });
            if registering && !self.events.room()? {
                return Ok(false);
            }
            let creating = matches!(&message, Message::Call { .. });
            let slot = if creating {
                Some(
                    self.calls
                        .iter()
                        .position(Option::is_none)
                        .ok_or(Fault::Capacity)?,
                )
            } else {
                None
            };
            let lease = if creating {
                match self.registry.call() {
                    Ok(lease) => Some(lease),
                    Err(Error::Protocol(Fault::Capacity)) => return Ok(false),
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
            let outcome = match self
                .session
                .core_mut()
                .ok_or(Fault::NotReady)?
                .client_request(&current, message, now, utc)
            {
                Ok(outcome) => outcome,
                Err(Fault::Capacity | Fault::WouldBlock) => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            if let RequestOutcome::Calling(id) = outcome {
                let index = slot.ok_or(Fault::Conflict)?;
                self.calls[index] = Some(Call {
                    id,
                    channel: None,
                    source: None,
                    gone: false,
                    retiring: None,
                    input: None,
                    _lease: lease.ok_or(Fault::Conflict)?,
                });
                self.report.calls_started = self.report.calls_started.saturating_add(1);
            }
            if !self.io.release_frame() {
                return Err(Fault::Conflict.into());
            }
            if !self.pending_allowed()? {
                return Err(Fault::Cancelled.into());
            }
            if registering {
                self.events.emit(LocalEvent::RegistrationAccepted)?;
            }
            self.first = None;
            self.client_input = None;
            self.mark();
            self.account()?;
            return Ok(true);
        }
        self.guard(cx)?;
        match self.io.poll_read(cx) {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(error)) => {
                self.client_lost = true;
                Err(error.into())
            }
            Poll::Ready(Ok(ReadStep::Eof)) => {
                self.client_lost = true;
                Err(Fault::Closed.into())
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.report.client_bytes_read = self
                    .report
                    .client_bytes_read
                    .checked_add(u64::try_from(bytes).map_err(|_| Fault::Overflow)?)
                    .ok_or(Fault::Overflow)?;
                // A prior partial target applies through this actual read. A
                // complete frame waiting for admission is no longer partial.
                if complete {
                    if self.client_input.is_some() {
                        self.refresh()?;
                        self.control
                            .check(self.sources.clock.as_ref(), self.session.core().is_some())?;
                    }
                    self.client_input = None;
                } else if bytes > 0 && self.client_input.is_none() {
                    self.client_input = Some(self.origin.after(self.limits.partial_input)?);
                }
                self.refresh()?;
                self.control
                    .check(self.sources.clock.as_ref(), self.session.core().is_some())?;
                Ok(bytes > 0)
            }
        }
    }
    pub(super) fn client_write(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        self.guard(cx)?;
        let Some(pending) = self.pending_client.as_mut() else {
            return Ok(false);
        };
        let id = pending.effect;
        let current = self.session.core().ok_or(Fault::NotReady)?.identity();
        if !self
            .session
            .core()
            .ok_or(Fault::NotReady)?
            .effect_io_allowed(id, &current, self.origin.now()?)?
        {
            return Err(Fault::Cancelled.into());
        }
        pending.attempted = true;
        match self.io.poll_write(cx) {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(error)) => {
                self.client_lost = true;
                Err(error.into())
            }
            Poll::Ready(Ok(WriteProgress {
                origin,
                bytes,
                complete,
            })) => {
                if origin.0 != id.value() {
                    return Err(Fault::StaleGeneration.into());
                }
                let pending = self.pending_client.as_mut().ok_or(Fault::Conflict)?;
                pending.written = pending.written.checked_add(bytes).ok_or(Fault::Overflow)?;
                self.report.client_bytes_written = self
                    .report
                    .client_bytes_written
                    .checked_add(u64::try_from(bytes).map_err(|_| Fault::Overflow)?)
                    .ok_or(Fault::Overflow)?;
                if complete {
                    self.pending_client
                        .as_mut()
                        .ok_or(Fault::Conflict)?
                        .known_written = true;
                    self.settle(id, Completion::Written)?;
                    self.pending_client = None;
                }
                Ok(true)
            }
        }
    }
    pub(super) fn peer_input(&mut self) -> Result<bool, Error> {
        let count = self.calls.len();
        for offset in 0..count {
            let index = (self.call_cursor + offset) % count;
            let Some(call) = self.calls[index].as_ref() else {
                continue;
            };
            if call.retiring.is_some() || call.gone {
                continue;
            }
            let Some(packet) = call.input.as_ref() else {
                continue;
            };
            if packet.waiting.is_some() {
                continue;
            }
            let id = call.id;
            let source = call.source.ok_or(Fault::NotReady)?;
            if !packet.validated {
                let call = self.calls[index].as_mut().ok_or(Fault::Stale)?;
                let packet = call.input.as_mut().ok_or(Fault::Stale)?;
                let bytes = packet.received.messages();
                let mut advanced = false;
                let mut failure = None;
                for _ in 0..self.limits.work_units {
                    if packet.validation == bytes.len() {
                        packet.validated = true;
                        break;
                    }
                    let rest = &bytes[packet.validation..];
                    match Frame::decode_prefix(rest).and_then(|(frame, _)| {
                        if frame.encoded_len() > self.limits.core.frame_bytes.min(64348) {
                            return Err(Fault::Capacity);
                        }
                        match Message::decode(&rest[..frame.encoded_len()])? {
                            Message::PeerRing { .. }
                            | Message::PeerControl(_)
                            | Message::PeerAudio(_) => Ok(frame.encoded_len()),
                            _ => Err(Fault::Malformed),
                        }
                    }) {
                        Ok(n) => {
                            packet.validation =
                                packet.validation.checked_add(n).ok_or(Fault::Overflow)?;
                            advanced = true;
                        }
                        Err(error) => {
                            failure = Some(error);
                            break;
                        }
                    }
                }
                if let Some(error) = failure {
                    return self.reject_call(index, error);
                }
                if packet.validation == bytes.len() {
                    packet.validated = true;
                }
                self.call_cursor = (index + 1) % count;
                return Ok(advanced || packet.validated);
            }
            let now = self.now()?;
            let utc = self.utc()?;
            let current = self.selected()?;
            let serial = self.next_delivery.ok_or(Fault::Overflow)?;
            let (end, result) = {
                let call = self.calls[index].as_ref().ok_or(Fault::Stale)?;
                let packet = call.input.as_ref().ok_or(Fault::Stale)?;
                if call.channel != Some(packet.received.channel()) || call.source != self.source {
                    return Err(Fault::StaleGeneration.into());
                }
                let bytes = packet.received.messages();
                let rest = bytes.get(packet.offset..).ok_or(Fault::Malformed)?;
                let (frame, _) = Frame::decode_prefix(rest)?;
                let message = Message::decode(&rest[..frame.encoded_len()])?;
                if let Message::PeerAudio(data) = &message {
                    let client_size = Message::Audio { cid: 0, data }.encoded_len()?;
                    if client_size > self.limits.core.frame_bytes
                        || client_size > self.limits.frame_bytes
                    {
                        return self.reject_call(index, Fault::TooLarge);
                    }
                }
                let end = packet
                    .offset
                    .checked_add(frame.encoded_len())
                    .ok_or(Fault::Overflow)?;
                (
                    end,
                    self.session
                        .core_mut()
                        .ok_or(Fault::NotReady)?
                        .receive(&current, id, source, serial, message, now, utc),
                )
            };
            match result {
                Ok(()) => {}
                Err(Fault::Capacity | Fault::WouldBlock) => continue,
                Err(error) => return self.reject_call(index, error),
            }
            self.next_delivery = serial.checked_add(1);
            let packet = self.calls[index]
                .as_mut()
                .and_then(|c| c.input.as_mut())
                .ok_or(Fault::Stale)?;
            packet.offset = end;
            packet.waiting = Some(serial);
            self.call_cursor = (index + 1) % count;
            self.mark();
            self.account()?;
            return Ok(true);
        }
        Ok(false)
    }
}
