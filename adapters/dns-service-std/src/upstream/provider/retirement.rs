//! Bounded old-generation callback debt, independent of active cache ownership.
use super::{Group, Peer, Provider};
use crate::upstream::UpstreamRetirement;
use std::task::{Context, Poll};

pub(super) fn poll_peer(
    peer: &mut Option<Peer>,
    cx: &mut Context<'_>,
    report: &mut UpstreamRetirement,
) {
    if let Some(owner) = peer
        && let Poll::Ready(receipt) = owner.connection.poll_retirement(cx)
    {
        report.native_connections = report.native_connections.saturating_add(1);
        if receipt.has_failure() {
            report.failures = report.failures.saturating_add(1);
            report.first.get_or_insert(receipt);
        }
        *peer = None;
    }
}
pub(super) fn drain(group: &mut Group, cx: &mut Context<'_>, report: &mut UpstreamRetirement) {
    for peer in &mut group.peers {
        poll_peer(peer, cx, report);
    }
}
impl Provider {
    /// Move a cancelled generation without dropping any original native loan.
    pub(super) fn park(&mut self, index: usize) -> bool {
        park_original(&mut self.groups[index], &mut self.retired)
    }
    pub(super) fn poll_retired(&mut self, cx: &mut Context<'_>) {
        for slot in &mut self.retired {
            if let Some(group) = slot {
                drain(group, cx, &mut self.retirement);
                if group.peers.iter().all(Option::is_none) {
                    *slot = None;
                }
            }
        }
    }
    pub fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<UpstreamRetirement> {
        if !self.core.is_stopped() {
            return Poll::Pending;
        }
        self.poll_retired(cx);
        for slot in &mut self.groups {
            if let Some(group) = slot {
                drain(group, cx, &mut self.retirement);
                if group.peers.iter().all(Option::is_none) {
                    *slot = None;
                }
            }
        }
        if self.groups.iter().chain(&self.retired).any(Option::is_some) {
            return Poll::Pending;
        }
        Poll::Ready(std::mem::take(&mut self.retirement))
    }
}

fn park_original<T>(current: &mut Option<T>, retired: &mut [Option<T>]) -> bool {
    let Some(slot) = retired.iter().position(Option::is_none) else {
        return false;
    };
    retired[slot] = current.take();
    true
}

#[cfg(test)]
mod tests {
    use super::park_original;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Original(Arc<AtomicUsize>);
    impl Drop for Original {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn full_retirement_arena_preserves_every_original_owner() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut current = Some(Original(drops.clone()));
        let mut retired = [None, None];
        assert!(park_original(&mut current, &mut retired));
        assert!(current.is_none());
        current = Some(Original(drops.clone()));
        assert!(park_original(&mut current, &mut retired));
        current = Some(Original(drops.clone()));
        assert!(!park_original(&mut current, &mut retired));
        assert!(current.is_some());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(retired[0].take());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(park_original(&mut current, &mut retired));
        assert!(current.is_none());
        drop(retired);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
    }
}
