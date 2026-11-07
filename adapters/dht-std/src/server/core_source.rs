//! One actual CORE client and its observed source phase. Closing is a request;
//! only the native Closed observation removes this owner from the Server.
use super::{Bound, Context, core};

pub(super) enum CorePhase<'id> {
    Connecting(Bound),
    Ready {
        bound: Bound,
        local: core::Peer<'id>,
    },
    Retiring,
}
impl CorePhase<'_> {
    pub(super) fn bound(&self) -> Option<&Bound> {
        match self {
            Self::Connecting(bound) | Self::Ready { bound, .. } => Some(bound),
            Self::Retiring => None,
        }
    }
    pub(super) fn ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
    pub(super) fn local_identity(&self) -> Option<[u8; 32]> {
        match self {
            Self::Ready { local, .. } => Some(local.identity().0),
            Self::Connecting(_) | Self::Retiring => None,
        }
    }
    pub(super) fn retiring(&self) -> bool {
        matches!(self, Self::Retiring)
    }
}

pub(super) struct CoreSource<'id> {
    pub(super) client: core::Client<'id, 256, 64>,
    pub(super) phase: CorePhase<'id>,
    // Partial input is independent of connection readiness and its source lease.
    pub(super) input: Option<Bound>,
}
impl CoreSource<'_> {
    /// Move the same client into retirement without creating a new lifetime.
    pub(super) fn retire(&mut self) {
        self.phase = CorePhase::Retiring;
        self.input = None;
    }
    /// Observe only original timers. Queries never replace or renew their bounds.
    pub(super) fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> bool {
        let source = match &mut self.phase {
            CorePhase::Connecting(bound) | CorePhase::Ready { bound, .. } => bound.poll_native(cx),
            CorePhase::Retiring => false,
        };
        source
            || self
                .input
                .as_mut()
                .is_some_and(|bound| bound.poll_native(cx))
    }
}
