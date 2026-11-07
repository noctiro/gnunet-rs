//! Borrow only actual carrier queues and their original completion debt. A pure
//! owner's frame can enter the selected native FIFO without an interim copy.
use super::*;
use gnunet_wire::official::dht::CoreEnvelope;

pub(super) fn request_available<'id>(
    core: Option<&CoreSource<'id>>,
    ip: Option<&crate::ip::Client<'id>>,
    native: NativePeer<'id>,
    frame: usize,
) -> Result<bool, Error> {
    match native {
        NativePeer::Core(peer) => {
            let length = frame.checked_add(4).ok_or(Fault::Overflow)?;
            core.ok_or(Fault::Closed)?
                .client
                .request_available(peer, length, length)
                .map_err(Into::into)
        }
        NativePeer::Ip(peer) => ip
            .ok_or(Fault::Closed)?
            .request_available(peer, frame)
            .map_err(Into::into),
    }
}

pub(super) struct Outgoing<'borrow, 'id> {
    core: &'borrow mut Option<CoreSource<'id>>,
    ip: &'borrow mut Option<crate::ip::Client<'id>>,
    sends: &'borrow mut Vec<Send<'id>>,
    clock: &'borrow dyn RuntimeClock,
    report: &'borrow mut Report,
    limit: usize,
}
impl<'borrow, 'id> Outgoing<'borrow, 'id> {
    pub(super) fn new(
        core: &'borrow mut Option<CoreSource<'id>>,
        ip: &'borrow mut Option<crate::ip::Client<'id>>,
        sends: &'borrow mut Vec<Send<'id>>,
        clock: &'borrow dyn RuntimeClock,
        report: &'borrow mut Report,
        limit: usize,
    ) -> Self {
        Self {
            core,
            ip,
            sends,
            clock,
            report,
            limit,
        }
    }
    /// Successful admission owns the only native payload allocation and its
    /// completion debt. Refusal leaves the borrowed pure frame untouched.
    pub(super) fn send(
        &mut self,
        native: NativePeer<'id>,
        job: Option<(Job<'id>, JobKind)>,
        frame: &[u8],
        bound: Bound,
    ) -> Result<bool, Error> {
        if self.sends.len() == self.limit
            || !request_available(self.core.as_ref(), self.ip.as_ref(), native, frame.len())?
        {
            return Ok(false);
        }
        bound.check(self.clock)?;
        let (id, frame_bytes) = match native {
            NativePeer::Core(peer) => {
                let envelope = CoreEnvelope::new(frame)?;
                let length = envelope.encoded_len()?;
                let mut bytes = discovery::buffer(length)?;
                envelope.encode(&mut bytes)?;
                let message = core::Message::try_from_owned(bytes).map_err(|error| error.reason)?;
                if Instant::now() >= bound.hard {
                    return Err(Fault::Deadline.into());
                }
                let priority = if matches!(job, Some((_, JobKind::Result))) {
                    2
                } else {
                    1
                };
                let id = self
                    .core
                    .as_mut()
                    .ok_or(Fault::Closed)?
                    .client
                    .send(peer, priority, bound.until, message)
                    .map_err(|error| error.reason)?;
                self.report.core_admitted = self.report.core_admitted.saturating_add(1);
                (NativeSend::Core(id), length + 48)
            }
            NativePeer::Ip(peer) => {
                let id = self
                    .ip
                    .as_mut()
                    .ok_or(Fault::Closed)?
                    .send(peer, frame, bound.hard)?;
                self.report.ip_admitted = self.report.ip_admitted.saturating_add(1);
                (NativeSend::Ip(id), frame.len() + 32)
            }
        };
        self.sends.push(Send {
            id,
            peer: native,
            job: job.map(|(job, _)| job),
            bound,
            cancelled: false,
            retirement: None,
            payload: None,
            frame_bytes,
        });
        Ok(true)
    }
}
