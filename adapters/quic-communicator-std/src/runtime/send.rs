//! One bounded MQ admission per queue, independent of HTTP stream availability.
use super::{Fault, Instant, MonoInstant, Protocol, Response, Runtime, ipc::Ipc, raw};
use zeroize::Zeroizing;

pub(super) enum Submission {
    Queued(Zeroizing<Vec<u8>>),
    Native,
    Retired,
}

/// A replacement MQ may restore this queue before its old native SEND drains.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum AdmissionCredit {
    Available,
    Withheld,
}

impl Runtime<'_, '_, '_, '_, '_> {
    pub(super) fn submit_queued(&mut self, i: usize, now: MonoInstant) -> Result<bool, Fault> {
        let row = self.rows[i].as_mut().ok_or(Protocol::Stale)?;
        let Some(send) = &mut row.send else {
            return Ok(false);
        };
        if !send.queued() || send.orphaned {
            return Ok(false);
        }
        let link = row.link.as_mut().ok_or(Protocol::NotReady)?;
        if !link.send_capacity(now)? {
            return Ok(false);
        }
        let Submission::Queued(bytes) =
            std::mem::replace(&mut send.submission, Submission::Retired)
        else {
            return Err(Protocol::Conflict.into());
        };
        // The original id/deadline and allocation move once. A failed native
        // admission is retired by this row's caller, never resubmitted.
        link.queue(send.id, bytes, send.hard, now)?;
        send.submission = Submission::Native;
        Ok(true)
    }
}

pub(super) struct Sending {
    pub(super) queue: u32,
    pub(super) orphaned: bool,
    pub(super) id: raw::SendId,
    pub(super) mid: [u8; 8],
    pub(super) submission: Submission,
    pub(super) accepted: usize,
    pub(super) total: usize,
    pub(super) result_queued: bool,
    pub(super) result_written: bool,
    pub(super) result_bytes: usize,
    pub(super) unknown: bool,
    pub(super) credit_queued: bool,
    pub(super) status: i32,
    pub(super) retiring: bool,
    pub(super) hard: Instant,
}
impl Sending {
    /// Admit the complete validated command before releasing its physical MQ
    /// frame. No native send is submitted or acknowledged at this boundary.
    pub(super) fn from_ipc(
        ipc: &mut Ipc,
        id: raw::SendId,
        mtu: u32,
        source_hard: Instant,
    ) -> Result<Self, Fault> {
        let Some(Response::Send(queue, mid, _, bytes)) = ipc.frame()? else {
            return Err(Protocol::Conflict.into());
        };
        let hard = ipc.input_hard().ok_or(Protocol::Conflict)?.min(source_hard);
        let send = Self::admit(queue, id, mid, bytes, mtu, hard)?;
        ipc.release()?;
        Ok(send)
    }
    fn admit(
        queue: u32,
        id: raw::SendId,
        mid: [u8; 8],
        bytes: &[u8],
        mtu: u32,
        hard: Instant,
    ) -> Result<Self, Protocol> {
        if Instant::now() >= hard {
            return Err(Protocol::Deadline);
        }
        gnunet_wire::official::Frame::decode(bytes)?;
        if bytes.len() > mtu as usize {
            return Err(Protocol::TooLarge);
        }
        let mut owned = Zeroizing::new(Vec::new());
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Protocol::Capacity)?;
        owned.extend_from_slice(bytes);
        Ok(Self {
            queue,
            orphaned: false,
            id,
            mid,
            submission: Submission::Queued(owned),
            accepted: 0,
            total: bytes.len(),
            result_queued: false,
            result_written: false,
            result_bytes: 0,
            unknown: false,
            credit_queued: false,
            status: 1,
            retiring: false,
            hard,
        })
    }
    pub(super) fn queued(&self) -> bool {
        matches!(self.submission, Submission::Queued(_))
    }
    /// Drop only never-submitted bytes; a native operation keeps its original
    /// acceptance/uncertainty and is never reconstructed after source loss.
    pub(super) fn retire_queued(&mut self) {
        if self.queued() {
            self.submission = Submission::Retired;
        }
    }
}

#[cfg(test)]
mod tests;
