//! PRE CADET events and classification of replies under their original tunnel.
use super::{Bound, Counter, Event, Failure, Fault, Owner, Received, TxKind, cadet, retryable};
use tokio::time::Instant;

#[cfg(all(test, feature = "program"))]
mod tests;

impl<'a, 'slots> Owner<'a, 'slots> {
    pub(super) fn on_cadet(&mut self, p: cadet::Step<'a>, now: u64) -> Result<Event, Failure> {
        self.blocked &= !8;
        match p {
            cadet::Step::Written(w) => {
                let Some(tx) = self.transmit.take() else {
                    return Err(Fault::Stale.into());
                };
                if tx.original != w.transmit {
                    return Err(Fault::Stale.into());
                }
                match tx.kind {
                    TxKind::Send(a) => match self.core.send_written(a) {
                        Ok(()) | Err(Fault::Stale) => {}
                        Err(e) => return Err(e.into()),
                    },
                    TxKind::Destroy(t) => {
                        if self.received.as_ref().is_some_and(|r| r.tunnel == t) {
                            self.received = None;
                        }
                        self.core.tunnel_stopped(t, now)?;
                        self.channels.retain(|c| c.tunnel != t)
                    }
                    TxKind::Open | TxKind::ReceiveDone => {}
                }
                Ok(Event::Cadet)
            }
            cadet::Step::Credit { channel, available } => {
                self.cadet_input_hard = None;
                if let Some(row) = self.channels.iter().find(|r| r.channel == Some(channel)) {
                    match self.core.channel_credit(row.tunnel, available, now) {
                        Ok(()) | Err(Fault::Stale | Fault::Deadline) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(Event::Cadet)
            }
            cadet::Step::Destroyed(channel) => {
                self.cadet_input_hard = None;
                if let Some(i) = self
                    .channels
                    .iter()
                    .position(|r| r.channel == Some(channel))
                {
                    if let Some(received) = self
                        .received
                        .as_mut()
                        .filter(|r| r.input.channel() == channel)
                    {
                        // Classify already-owned replies before resetting this
                        // tunnel's DNS IDs or reselecting unanswered requests.
                        received.needs_ack = false;
                        self.channels[i].remote_closed = true;
                    } else {
                        let row = self.channels.remove(i);
                        self.core.tunnel_stopped(row.tunnel, now)?;
                    }
                }
                Ok(Event::Cadet)
            }
            cadet::Step::Data(input) => {
                self.cadet_input_hard = None;
                if self.received.is_some() {
                    return Err(Fault::Capacity.into());
                }
                let row = self
                    .channels
                    .iter()
                    .find(|row| row.channel == Some(input.channel()))
                    .ok_or(Fault::Stale)?;
                if row.destroying || row.remote_closed {
                    // Known local/remote retirement cannot acquire new input.
                    return Ok(Event::Cadet);
                }
                self.received = Some(Received {
                    input,
                    tunnel: row.tunnel,
                    peer: row.peer,
                    cursor: 0,
                    processed: false,
                    needs_ack: true,
                    bounds: Bound::after(now, self.limits.control_timeout)?,
                });
                Ok(Event::Cadet)
            }
            cadet::Step::Lost { .. } => {
                self.transmit = None;
                self.received = None;
                self.cadet_input_hard = None;
                for row in self.channels.drain(..) {
                    match self.core.tunnel_stopped(row.tunnel, now) {
                        Ok(()) | Err(Fault::Stale) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(Event::Cadet)
            }
            cadet::Step::Activity { read_bytes, .. } => {
                if read_bytes > 0 && self.cadet_input_hard.is_none() {
                    self.cadet_input_hard = Some(
                        Instant::now()
                            .checked_add(self.limits.control_timeout)
                            .ok_or(Fault::Overflow)?,
                    )
                }
                Ok(Event::Activity)
            }
            cadet::Step::RejectedIncoming { transmit, .. } => {
                self.cadet_input_hard = None;
                self.actual_tx(
                    transmit,
                    Bound::after(now, self.limits.control_timeout)?,
                    TxKind::ReceiveDone,
                )?;
                Ok(Event::Cadet)
            }
            cadet::Step::Blocked {
                input_retained: true,
                ..
            } => {
                self.blocked |= 8;
                if self.cadet_input_hard.is_none() {
                    self.cadet_input_hard = Some(
                        Instant::now()
                            .checked_add(self.limits.control_timeout)
                            .ok_or(Fault::Overflow)?,
                    );
                }
                self.delay()?;
                Ok(Event::Backpressure)
            }
            cadet::Step::Blocked { .. }
            | cadet::Step::ConnectRetry { .. }
            | cadet::Step::Unavailable(_) => {
                self.blocked |= 8;
                self.delay()?;
                Ok(Event::Backpressure)
            }
            cadet::Step::Ignored { .. } | cadet::Step::Incoming { .. } => {
                self.cadet_input_hard = None;
                Ok(Event::Cadet)
            }
            cadet::Step::Connected(_) | cadet::Step::WaitDeadline => Ok(Event::Cadet),
            cadet::Step::Closed => Err(Fault::Closed.into()),
        }
    }
    pub(super) fn pre_receive(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        if self.received.is_some() {
            let r = self.received.as_mut().ok_or(Fault::Conflict)?;
            let mut progressed = false;
            if !r.processed {
                let bytes = r.input.messages();
                // One application frame per turn leaves ready DNS output and
                // native source retirement a scheduling point between frames.
                if r.cursor < bytes.len() {
                    let result = gnunet_wire::official::Frame::decode_prefix(&bytes[r.cursor..]);
                    let (valid, end) = match result {
                        Ok((frame, _)) => {
                            let end = r
                                .cursor
                                .checked_add(frame.encoded_len())
                                .ok_or(Fault::Overflow)?;
                            (
                                self.core.response(r.tunnel, &bytes[r.cursor..end], now),
                                end,
                            )
                        }
                        Err(error) => (Err(error), r.cursor),
                    };
                    match valid {
                        Ok(accepted) => {
                            self.metrics.bump(if accepted {
                                Counter::Received
                            } else {
                                Counter::Late
                            });
                            r.cursor = end;
                            progressed = true;
                        }
                        Err(_) => {
                            // Reply storage was reserved before query admission.
                            // A parser/size refusal is a fixed policy limit;
                            // waiting cannot make the retained packet admissible.
                            self.core.withdraw_exit(r.peer)?;
                            return Ok(Some(Event::Activity));
                        }
                    }
                }
                r.processed = r.cursor == bytes.len();
                if !r.processed {
                    return Ok(Some(Event::Activity));
                }
            }
            if !r.needs_ack {
                let received = self.received.take().ok_or(Fault::Conflict)?;
                if let Some(index) = self
                    .channels
                    .iter()
                    .position(|row| row.tunnel == received.tunnel)
                {
                    let row = self.channels.remove(index);
                    self.core.tunnel_stopped(row.tunnel, now)?;
                }
                // Native channel is gone. Release only the local packet; its
                // old Delivery cannot authorize receive_done or a new ACK.
                return Ok(Some(Event::Cadet));
            }
            if self.transmit.is_none() {
                match self
                    .cadet
                    .as_mut()
                    .ok_or(Fault::Unavailable)?
                    .receive_done(r.input.delivery())
                {
                    Ok(tx) => {
                        let r = self.received.take().ok_or(Fault::Conflict)?;
                        self.actual_tx(tx, r.bounds, TxKind::ReceiveDone)?;
                        return Ok(Some(Event::Admitted));
                    }
                    Err(e) if retryable(&e) => {
                        self.delay()?;
                        return Ok(Some(Event::Backpressure));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if progressed {
                return Ok(Some(Event::Activity));
            }
        }
        Ok(None)
    }
}
