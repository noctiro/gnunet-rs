//! Production shared-allocator submission. Owner remains the sole reservation
//! worker poller; no callback is relabelled or independently polled here.
use crate::{Failure, dv_schedule::Scheduler, owner::Owner, sender::DvScope};
use gnunet_crypto::Entropy;
use gnunet_transport_dv_bridge_host::{self as bridge, Actor, Bridge, Origin, VirtualIntent};
use gnunet_transport_dv_runtime_host as actor;
/// Actual progress only; waiting is neither a new request nor successful send.
pub enum Progress<'id> {
    /// No original common-transmit packet is ready.
    Idle,
    /// Same original packet/budget waits for actual committed DV range.
    WaitingForRange,
    /// Original retired never-admitted staging was actually discarded.
    Retired,
    /// Same packet/lease admitted to real Actor with a real persisted stamp.
    Submitted(actor::Token<'id>),
    /// Actual zero-admission refusal, preserving the original opaque metadata.
    Refused(actor::Refused<Origin>),
}
/// One bounded original range wait. The immutable parent Job budget is captured
/// once; lack of range/Actor capacity cannot renew it or emit a second output.
#[derive(Default)]
pub struct Transmit<'id> {
    waiting: Option<VirtualIntent<'id>>,
}
impl<'id> Transmit<'id> {
    /// No source, worker, entropy, clock or allocation is created.
    pub const fn new() -> Self {
        Self { waiting: None }
    }
    /// Source retirement drops only never-submitted interest. Bridge/Engine keep
    /// exact original cleanup obligations; no worker/native receipt is forged.
    pub fn close(&mut self) {
        self.waiting = None;
    }
    /// Borrow Owner only outside its callback. The actual Scheduler consumes
    /// private CommittedRange-backed Stamp with same Scope/Identity/Budget, then
    /// the real bridge calls Actor.send_with_options before any await/reentry.
    pub fn drive<'source, 'pils, 'slots, 'out, 'owner, E: Entropy, P: Entropy, const N: usize>(
        &mut self,
        bridge: &mut Bridge<'id>,
        actor: &mut Actor<'id, 'source, 'pils, 'slots, 'out, N>,
        owner: &mut Owner<'owner, E>,
        scheduler: &mut Scheduler<'id, 'pils, 'owner>,
        scope: &DvScope<'owner>,
        entropy: &mut P,
    ) -> Result<Progress<'id>, Failure> {
        let times = owner.dv_times(scope)?;
        {
            let server = owner.dv_server(scope)?;
            if bridge.discard_retired(server, times)? {
                return Ok(Progress::Retired);
            }
            if self
                .waiting
                .as_ref()
                .is_some_and(|i| !bridge.intent_live(server, i))
            {
                self.waiting = None;
            }
            if self.waiting.is_none() {
                self.waiting = bridge.prepare_virtual(server, actor)?;
            }
        }
        let Some(original) = self.waiting.as_ref() else {
            return Ok(Progress::Idle);
        };
        let budget = original.budget();
        let Some(stamp) = scheduler.claim_stamp(actor, owner, budget)? else {
            return Ok(Progress::WaitingForRange);
        };
        let scalar = stamp.consume(actor, owner, budget)?;
        let original = self.waiting.take().ok_or(gnunet_types::Error::Stale)?;
        let result =
            bridge.send_virtual(owner.dv_server(scope)?, actor, original, scalar, entropy)?;
        Ok(match result {
            bridge::SendVirtual::Submitted(id) => Progress::Submitted(id),
            bridge::SendVirtual::Deferred(original) => Progress::Refused(original),
        })
    }
}
