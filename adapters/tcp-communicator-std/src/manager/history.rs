//! Original task registry and clock-free local durability retirement. All PS
//! callback/iterator/epoch ownership remains in the original manager rows.
use super::*;
use crate::history::{HistoryProgress, ReplayHistory, ReplayTask};
pub(super) struct Claim {
    pub(super) task: ReplayTask,
    pub(super) key: Key,
    pub(super) query: usize,
    pub(super) store: Option<usize>,
    pub(super) retiring: bool,
    pub(super) requested: bool,
    pub(super) retired: bool,
}
impl Communicator<'_> {
    pub(super) fn poll_history(
        &mut self,
        cx: &mut Context<'_>,
        ports: &mut impl ReplayHistory,
    ) -> Poll<Result<Activity, HostError>> {
        for i in 0..self.histories.len() {
            let Some(claim) = self.histories[i].as_mut() else {
                continue;
            };
            let live = self.slots.get(claim.key.index).is_some_and(|slot| {
                slot.generation == claim.key.generation
                    && slot.peer.as_ref().is_some_and(|p| {
                        !matches!(
                            p.core.phase(),
                            Phase::Finishing | Phase::Closing | Phase::Detached | Phase::Closed
                        )
                    })
            });
            let referenced = self
                .queries
                .get(claim.query)
                .and_then(Option::as_ref)
                .is_some_and(|row| row.history == i)
                || claim
                    .store
                    .and_then(|index| self.stores.get(index))
                    .and_then(Option::as_ref)
                    .is_some_and(|row| row.history == i);
            if !live || !referenced {
                claim.retiring = true;
            }
            if claim.retiring && !claim.requested {
                match ports.retire_history(&claim.task) {
                    Ok(()) => {
                        claim.requested = true;
                        return Poll::Ready(Ok(Activity::Callback));
                    }
                    Err(Error::WouldBlock) => {}
                    Err(error) => return Poll::Ready(Err(error.into())),
                }
            }
            if claim.retired && !referenced {
                self.histories[i] = None;
                return Poll::Ready(Ok(Activity::Callback));
            }
        }
        match ports.poll_history(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(HistoryProgress::Activity)) => Poll::Ready(Ok(Activity::Callback)),
            Poll::Ready(Ok(HistoryProgress::Retired { task, .. })) => {
                let claim = self
                    .histories
                    .iter_mut()
                    .flatten()
                    .find(|claim| claim.task == task)
                    .ok_or(Error::Stale)?;
                if !claim.retiring || !claim.requested {
                    return Poll::Ready(Err(Error::Stale.into()));
                }
                claim.retired = true;
                Poll::Ready(Ok(Activity::Callback))
            }
        }
    }
}
