//! Exact per-connection driver, SEND, callback and frame-loan retirement.
use super::{
    AdmissionCredit, Event, Fault, Instant, MonoInstant, Protocol, Request, Runtime, capture_send,
    ipc, queue,
};

impl<'id, 'pils, 'pool, 'slots, 'buf> Runtime<'id, 'pils, 'pool, 'slots, 'buf> {
    pub(super) fn retire_row(
        &mut self,
        i: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let bound = self.deadline(self.limits.close_grace)?;
        let row = self.rows[i].as_mut().ok_or(Protocol::Stale)?;
        if row.closing {
            return Ok(false);
        }
        row.closing = true;
        // Late polling cannot turn an expired original operation into a fresh
        // close allowance. Driver/socket teardown remains original-source work.
        let mut anchor = Instant::now().min(row.hard).min(row.idle);
        if let Some(t) = row.input {
            anchor = anchor.min(t)
        }
        if let Some(s) = &row.send {
            anchor = anchor.min(s.hard)
        }
        row.retire_hard = Some(
            anchor
                .checked_add(self.limits.close_grace)
                .ok_or(Protocol::Overflow)?
                .min(self.hard),
        );
        row.input = None;
        if let Some(connecting) = row.connecting.take() {
            drop(connecting)
        }
        capture_send(row)?;
        if let Some(send) = &mut row.send {
            send.retire_queued();
        }
        if let Some(link) = &mut row.link {
            link.close()
        }
        if row.send.as_ref().is_some_and(|send| send.orphaned) {
            row.send = None;
        }
        if let Some(send) = &mut row.send
            && !send.result_queued
        {
            send.status = -1;
            send.retiring = true;
            send.hard = send
                .hard
                .checked_add(self.limits.close_grace)
                .ok_or(Protocol::Overflow)?
                .min(bound)
                .min(self.hard)
        }
        if row
            .send
            .as_ref()
            .is_some_and(|s| s.result_written && !s.credit_queued)
        {
            let send = row.send.take().ok_or(Protocol::Stale)?;
            self.sends_retired += 1;
            observe(Event::SendRetired {
                epoch: self.epoch,
                queue: send.queue,
                message_id: send.mid,
                accepted: send.accepted,
                total: send.total,
                result_written: true,
                result_bytes: send.result_bytes,
                unknown: send.unknown,
            });
        }
        self.endpoint
            .as_mut()
            .ok_or(Protocol::Closed)?
            .retire_driver_at(&row.driver, row.retire_hard.ok_or(Protocol::Conflict)?)?;
        observe(Event::QueueRetired {
            epoch: self.epoch,
            queue: row.id,
        });
        Ok(true)
    }
    pub(super) fn maintenance(
        &mut self,
        mono: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let mut progress = false;
        let now = Instant::now();
        for i in 0..self.rows.len() {
            let Some(row) = &self.rows[i] else { continue };
            if row.incoming.as_ref().is_some_and(|d| now >= d.hard) {
                return Err(Protocol::Deadline.into());
            }
            // Retire the exact original driver before enforcing its row's
            // cleanup deadline. Maintenance runs before the backend poll, so an
            // expired driver must not require another backend turn to stop.
            if row.closing {
                let retired = self.driver_retired(i, now)?;
                let row = self.rows[i].as_ref().ok_or(Protocol::Stale)?;
                if retired && row.send.is_none() && row.incoming.is_none() && row.down_written {
                    self.reap_row(i, observe)?;
                    progress = true;
                    continue;
                }
                // Remaining callback/output debt cannot be acknowledged or
                // erased merely because the original native driver stopped.
                if row.retire_hard.is_some_and(|t| now >= t) {
                    return Err(Protocol::Deadline.into());
                }
            }
            let row = self.rows[i].as_ref().ok_or(Protocol::Stale)?;
            if row
                .send
                .as_ref()
                .is_some_and(|s| !s.orphaned && now >= s.hard && (s.retiring || s.result_queued))
            {
                return Err(Protocol::Deadline.into());
            }
            if !row.closing
                && (now >= row.hard
                    || now >= row.idle
                    || row.input.is_some_and(|h| now >= h)
                    || row.send.as_ref().is_some_and(|s| now >= s.hard))
            {
                progress |= self.retire_row(i, observe)?
            }
            // Native stream pressure belongs to this original SEND, never to
            // the shared MQ cursor or unrelated queues' FC callbacks.
            if !self.rows[i].as_ref().ok_or(Protocol::Stale)?.closing {
                match self.submit_queued(i, mono) {
                    Ok(submitted) => progress |= submitted,
                    Err(error) => {
                        observe(Event::Rejected(error));
                        progress |= self.retire_row(i, observe)?;
                    }
                }
            }
            let row = self.rows[i].as_mut().ok_or(Protocol::Stale)?;
            if row
                .send
                .as_ref()
                .is_some_and(|send| send.orphaned && send.accepted == send.total)
            {
                let send = row.send.as_ref().ok_or(Protocol::Stale)?;
                if !send.result_written {
                    row.link
                        .as_mut()
                        .ok_or(Protocol::Stale)?
                        .take_accepted(send.id)?;
                }
                row.send = None;
                progress = true;
            }
            if let Some(send) = &mut row.send {
                if send.orphaned {
                    continue;
                }
                if !send.result_queued && (send.accepted == send.total || row.closing) {
                    let result = Request::Sent {
                        message_id: send.mid,
                        queue: row.id,
                        peer: row.peer.ok_or(Protocol::Stale)?,
                        status: send.status,
                    };
                    if self.ipc.room_request(result)? {
                        self.ipc
                            .enqueue(result, ipc::Role::Sent(row.id, send.mid), send.hard)?;
                        send.result_queued = true;
                        progress = true
                    }
                }
                if send.result_written && !send.credit_queued && !row.closing {
                    let hard = send.hard;
                    let update = Request::QueueUpdate(queue(row, 1)?);
                    if self.ipc.room_request(update)? {
                        self.ipc.enqueue(update, ipc::Role::Credit(row.id), hard)?;
                        // Borrow ends before mutating the same original send row.
                        row.send.as_mut().ok_or(Protocol::Stale)?.credit_queued = true;
                        progress = true;
                    }
                }
            }
            if !row.closing
                && row.admission == AdmissionCredit::Withheld
                && row.send.is_none()
                && row.queue_written
            {
                let update = Request::QueueUpdate(queue(row, 1)?);
                if self.ipc.room_request(update)? {
                    self.ipc
                        .enqueue(update, ipc::Role::Available(row.id), self.hard)?;
                    row.admission = AdmissionCredit::Available;
                    progress = true;
                }
            }
            if row.closing && !row.down {
                if !row.advertised {
                    row.down = true;
                    row.down_written = true
                } else {
                    let down = Request::QueueDown(row.id, row.peer.ok_or(Protocol::Stale)?);
                    if self.ipc.room_request(down)? {
                        self.ipc.enqueue(down, ipc::Role::Down(row.id), self.hard)?;
                        row.down = true;
                        row.down_written = false;
                        progress = true
                    }
                }
            }
            let removable = row.closing
                && row.send.is_none()
                && row.incoming.is_none()
                && row.down_written
                && self
                    .endpoint
                    .as_ref()
                    .ok_or(Protocol::Closed)?
                    .driver_done(&row.driver)?;
            if removable {
                self.reap_row(i, observe)?;
                progress = true;
            }
        }
        Ok(progress)
    }
    pub(super) fn reap_row(
        &mut self,
        i: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let row = self.rows[i].as_ref().ok_or(Protocol::Stale)?;
        let forced = self
            .endpoint
            .as_ref()
            .ok_or(Protocol::Closed)?
            .driver_was_canceled(&row.driver)?;
        self.endpoint
            .as_mut()
            .ok_or(Protocol::Closed)?
            .release_driver(&row.driver)?;
        let row = self.rows[i].take().ok_or(Protocol::Stale)?;
        if let Some(link) = row.link {
            link.recycle(&mut self.loans, i)?
        }
        observe(Event::DriverRetired {
            epoch: self.epoch,
            queue: row.id,
            forced,
        });
        Ok(forced)
    }
    pub(super) fn driver_retired(&mut self, i: usize, now: Instant) -> Result<bool, Fault> {
        let row = self.rows[i].as_ref().ok_or(Protocol::Stale)?;
        let endpoint = self.endpoint.as_mut().ok_or(Protocol::Closed)?;
        if endpoint.driver_done(&row.driver)? {
            return Ok(true);
        }
        if row.retire_hard.is_some_and(|until| now >= until) {
            endpoint.cancel_driver(&row.driver)?;
            return Ok(endpoint.driver_done(&row.driver)?);
        }
        Ok(false)
    }
}
