//! One ordinary autonomous FIND PEER controller, without a fake local MQ.
//! A round waits for bounded business credit with its original target; all
//! actual frames then use existing original Work/CORE/PILS ownership.
use crate::{
    Cause, Error,
    budget::{Anchor, Bound},
};
use gnunet_crypto::Entropy;
use gnunet_dht::network::{NetworkBlocks, NetworkOwner};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{task::Context, time::Duration};
const MINIMUM: u64 = 120_000_000;
const AVERAGE: u64 = 6_000_000;
#[derive(Clone, Copy, Eq, PartialEq)]
struct Credit {
    frames: usize,
    bytes: usize,
    peers: usize,
}
struct Round {
    bound: Bound,
    anchor: Anchor,
    blocked: Option<Credit>,
}
pub(crate) enum Step {
    Idle,
    Skipped,
    Expired,
    Prepared { frames: usize, anchor: Anchor },
}
pub(crate) struct Controller {
    enabled: bool,
    active: bool,
    due: bool,
    next: Option<Bound>,
    round: Option<Round>,
    new_peers: u64,
}
impl Controller {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            active: false,
            due: false,
            next: None,
            round: None,
            new_peers: 0,
        }
    }
    pub fn connected(&mut self, first: bool, eligible: bool) {
        if !self.enabled {
            return;
        }
        if eligible {
            self.new_peers = self.new_peers.saturating_add(1);
        }
        if first {
            self.active = true;
            self.due = true;
        }
        self.resume();
    }
    pub fn resume(&mut self) {
        if let Some(round) = &mut self.round {
            round.blocked = None;
        }
    }
    pub fn empty(&mut self) {
        self.active = false;
        self.due = false;
        self.next = None;
        self.round = None;
        self.new_peers = 0;
    }
    /// Register old native alarms before any source-clock/provider operation.
    /// Only an unadmitted local round is discarded here, never a CORE send.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> bool {
        if !self.active {
            return false;
        }
        if !self.due && self.next.as_mut().is_some_and(|b| b.poll_native(cx)) {
            self.due = true;
        }
        if self.round.as_mut().is_some_and(|r| r.bound.poll_native(cx)) {
            self.round = None;
            return true;
        }
        false
    }
    pub fn step(
        &mut self,
        owner: &mut NetworkOwner<'_>,
        clock: &dyn RuntimeClock,
        limits: &crate::Limits,
        now: u64,
        blocks: &mut impl NetworkBlocks,
        entropy: &mut impl Entropy,
    ) -> Result<Step, Error> {
        if !self.active || !self.enabled {
            return Ok(Step::Idle);
        }
        if self.next.as_ref().is_some_and(|b| now >= b.until) {
            self.due = true;
        }
        if self.round.is_none() {
            if !self.due {
                return Ok(Step::Idle);
            }
            // Capture the original operation hard before entropy/clock setup.
            let bound = Bound::new(clock, limits.output_lifetime)?;
            let anchor = bound.check(clock)?;
            let divisor = u64::try_from(limits.network.bucket_size).map_err(|_| Fault::Overflow)?;
            if divisor == 0 {
                return Err(Fault::InvalidInput.into());
            }
            let scale = self
                .new_peers
                .checked_add(1)
                .and_then(|n| n.checked_mul(100))
                .ok_or(Fault::Overflow)?
                / divisor;
            let span = AVERAGE
                .checked_mul(scale.checked_add(1).ok_or(Fault::Overflow)?)
                .ok_or(Fault::Overflow)?;
            let mut bytes = [0; 8];
            entropy.fill(&mut bytes)?;
            let delay = MINIMUM
                .checked_add(u64::from_ne_bytes(bytes) % span)
                .ok_or(Fault::Overflow)?;
            self.next = Some(Bound::new(clock, Duration::from_micros(delay))?);
            self.due = false;
            let skip = self.new_peers > divisor;
            self.new_peers = 0;
            if skip {
                return Ok(Step::Skipped);
            }
            self.round = Some(Round {
                bound,
                anchor,
                blocked: None,
            });
        }
        let snapshot = owner.snapshot();
        let credit = Credit {
            frames: snapshot.jobs,
            bytes: snapshot.bytes,
            peers: snapshot.peers,
        };
        let round = self.round.as_ref().ok_or(Fault::NotReady)?;
        match round.bound.check(clock) {
            Ok(_) => {}
            Err(Error(cause)) if matches!(cause.as_ref(), Cause::Protocol(Fault::Deadline)) => {
                self.round = None;
                return Ok(Step::Expired);
            }
            Err(e) => return Err(e),
        }
        if round.blocked == Some(credit) {
            return Ok(Step::Idle);
        }
        let result = owner.find_peers(now, round.bound.until, blocks, entropy);
        match result {
            Ok(frames) => {
                let round = self.round.take().ok_or(Fault::Stale)?;
                Ok(Step::Prepared {
                    frames,
                    anchor: round.anchor,
                })
            }
            Err(Fault::Capacity | Fault::WouldBlock) => {
                self.round.as_mut().ok_or(Fault::Stale)?.blocked = Some(credit);
                Ok(Step::Idle)
            }
            Err(Fault::Deadline) => {
                self.round = None;
                Ok(Step::Expired)
            }
            Err(e) => Err(e.into()),
        }
    }
}
