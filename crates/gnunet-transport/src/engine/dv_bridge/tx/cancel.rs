//! Synchronous cancellation of fully located, never-native original chunks.
use super::*;

/// Read-only view of the actual immutable frame held by the native owner.
/// Constructing this view alone does not prove that a frame is unqueued; the
/// caller must first exclude native tags for this original transfer.
pub struct StagedSend<'a> {
    /// Original physical communicator MQ, not a peer-selected replacement.
    pub owner: &'a ClientId,
    /// Same Engine-branded chunk recognized while its ledger remains live.
    pub send: &'a SendId,
    /// Actual complete held1209 bytes; neither copied nor regenerated.
    pub bytes: &'a [u8],
}

/// Actual local cancellation boundary, without a wire CANCEL or delivery ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferCancellation {
    /// All original chunks were located before native admission and removed.
    Unsent {
        /// Caller must synchronously drop its SAME supplied pending frame.
        /// No fallible work or native IO may intervene after this result.
        pending: bool,
    },
    /// Native admission/exposure or an unlocated original prevents a local
    /// rollback. Nothing changed; retire the original physical source instead.
    NeedsRetirement,
}

struct Plan {
    transfer: usize,
    job: u64,
    charge: usize,
    peer: PeerId,
    pending: bool,
    route: Option<(usize, u64, u64)>,
}
fn belongs(row: &SendRow, parent: &TransferId) -> bool {
    row.parent.as_ref().is_some_and(|(id, _)| id == parent)
}
fn frame_matches(row: &SendRow, owner: &ClientId, bytes: &[u8]) -> bool {
    *owner == row.queue.owner
        && Frame::decode(bytes).is_ok_and(|f| f.header().message_type().value() == 1209)
        && bytes.get(4..8) == Some(row.queue.queue.to_be_bytes().as_slice())
        && bytes.get(8..16) == Some(row.id.mid.as_slice())
        && bytes.get(16..48) == Some(row.queue.peer.0.as_slice())
}
fn attempt_matches(row: &SendRow, attempt: &Attempt) -> bool {
    attempt.owner == row.queue.owner
        && attempt.peer == row.queue.peer
        && attempt.queue == row.queue.queue
        && attempt.route == row.queue.route
        && attempt.message_id == row.id.mid
}
impl Engine {
    fn dv_cancel_plan(
        &self,
        id: &TransferId,
        pending: Option<&StagedSend<'_>>,
    ) -> Result<Option<Plan>, Error> {
        let transfer = self
            .dv_bridge
            .tx
            .transfers
            .iter()
            .position(|t| t.id == *id)
            .ok_or(Error::Stale)?;
        let t = &self.dv_bridge.tx.transfers[transfer];
        if t.packet_observed
            || t.state.queued
            || t.state.exposed
            || !matches!(t.state.outcome, None | Some(TransferOutcome::Unsent))
        {
            return Ok(None);
        }
        let mut held = false;
        let mut refundable = 0u64;
        let mut inflight = 0u64;
        for row in self.dv_bridge.sends.iter().filter(|row| belongs(row, id)) {
            if !Arc::ptr_eq(&row.id.instance, &self.instance)
                || row.queue != t.queue
                || row.state.ipc_exposed
                || row.state.ipc_written
                || row.state.packet.is_some()
                || self
                    .dv_bridge
                    .sends
                    .iter()
                    .filter(|r| r.id == row.id)
                    .count()
                    != 1
            {
                return Ok(None);
            }
            let output_count = self
                .output
                .iter()
                .filter(|output| {
                    matches!(output, Output::Frame { client, bytes }
                        if frame_matches(row, client, bytes))
                })
                .count();
            let held_count = if let Some(pending) = pending {
                let same_id = *pending.send == row.id;
                let same_frame = frame_matches(row, pending.owner, pending.bytes);
                if same_id != same_frame {
                    return Ok(None);
                }
                usize::from(same_id)
            } else {
                0
            };
            if output_count.checked_add(held_count) != Some(1) {
                return Ok(None);
            }
            held |= held_count != 0;
            refundable = refundable
                .checked_add(u64::from(row.queue_debit))
                .ok_or(Error::Overflow)?;
            for (records, (attempt, active)) in self
                .attempts
                .iter()
                .map(|attempt| (attempt, true))
                .chain(self.completed.iter().map(|attempt| (attempt, false)))
                .filter(|(attempt, _)| attempt.message_id == row.id.mid)
                .enumerate()
            {
                if !attempt_matches(row, attempt) || records != 0 {
                    return Ok(None);
                }
                if active && !attempt.retired {
                    inflight = inflight.checked_add(1).ok_or(Error::Overflow)?;
                }
            }
        }
        // Every chunk above belongs to this one original route generation.
        // Keep its checked update in the stack plan; do not scan every other
        // route or repeat the send/attempt joins during the commit.
        let route = if let Some(index) = self.routes.iter().position(|q| q.serial == t.queue.route)
        {
            let route = &self.routes[index];
            if route.owner != t.queue.owner
                || route.description.peer != t.queue.peer
                || route.description.id != t.queue.queue
            {
                return Ok(None);
            }
            route
                .inflight
                .checked_sub(inflight)
                .ok_or(Error::Overflow)?;
            let refundable = if route.unlimited { 0 } else { refundable };
            route
                .available
                .checked_add(refundable)
                .ok_or(Error::Overflow)?;
            Some((index, refundable, inflight))
        } else {
            None
        };
        let charge = self
            .jobs
            .iter()
            .find(|j| j.id == t.job)
            .map_or(0, Job::charge);
        self.buffered.checked_sub(charge).ok_or(Error::Overflow)?;
        Ok(Some(Plan {
            transfer,
            job: t.job,
            charge,
            peer: t.queue.peer,
            pending: held,
            route,
        }))
    }

    /// Cancel only completely located original chunks before native admission.
    /// The caller excludes its actual native tags first, supplies its real held
    /// frame, and drops that SAME frame synchronously after `pending: true`.
    /// Every rejection leaves all protocol owners and counters unchanged.
    pub fn dv_cancel_pre_native_transfer(
        &mut self,
        id: &TransferId,
        pending: Option<StagedSend<'_>>,
    ) -> Result<TransferCancellation, Error> {
        let Some(plan) = self.dv_cancel_plan(id, pending.as_ref())? else {
            return Ok(TransferCancellation::NeedsRetirement);
        };
        // All checked arithmetic and ownership validation preceded mutation.
        // An expired attempt already left inflight. A removed original route
        // cannot transfer its old grant to a replacement with the same qid.
        if let Some((index, refundable, inflight)) = plan.route {
            let route = &mut self.routes[index];
            route.inflight -= inflight;
            route.available += refundable;
        }
        let sends = &self.dv_bridge.sends;
        self.output.retain(|output| {
            !matches!(output, Output::Frame { client, bytes }
                if sends.iter().any(|row| belongs(row, id) && frame_matches(row, client, bytes)))
        });
        self.attempts.retain(|attempt| {
            !sends
                .iter()
                .any(|row| belongs(row, id) && attempt_matches(row, attempt))
        });
        self.completed.retain(|attempt| {
            !sends
                .iter()
                .any(|row| belongs(row, id) && attempt_matches(row, attempt))
        });
        self.dv_bridge.sends.retain(|row| !belongs(row, id));
        let job_pending = self.jobs.iter().any(|job| job.id == plan.job);
        self.jobs.retain(|job| job.id != plan.job);
        self.buffered -= plan.charge;
        self.remote_acks.remove_job(plan.job);
        if job_pending {
            self.dv_bridge.job_retired(plan.job);
        }
        let state = &mut self.dv_bridge.tx.transfers[plan.transfer].state;
        state.outcome = Some(TransferOutcome::Unsent);
        state.job_pending = false;
        if let Some(peer) = self.peers.iter_mut().find(|p| p.id == plan.peer) {
            // The historical sent counter may already be in an immutable FLOW
            // frame. Never subtract it or invent receive/ACK coverage; the real
            // FLOW loss correction restores the original peer's usable window.
            peer.flow_dirty = true;
            peer.flow_next = peer.flow_next.min(self.last_monotonic);
        }
        Ok(TransferCancellation::Unsent {
            pending: plan.pending,
        })
    }
}

#[cfg(test)]
mod tests;
