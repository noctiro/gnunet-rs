//! Resume a saved selector without releasing the original checkpoint lock.
use super::{Journal, Observation, OpenError, OpenStage, State, fail};
use crate::platform;
use std::io;
pub(super) fn restore(mut journal: Journal) -> Result<Journal, OpenError> {
    if let Some(State::Creating(intent)) = journal.state().cloned() {
        if let Err(error) = journal.fence_intent(&intent) {
            return Err(fail(OpenStage::Recover, error, Some(journal), None));
        }
        let selected = match platform::discover_allocation(&intent) {
            Ok(selected) => selected,
            Err(error) => return Err(fail(OpenStage::Recover, error, Some(journal), None)),
        };
        let Some(record) = selected else {
            return Err(fail(
                OpenStage::PendingAllocation,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "allocation intent has no unique complete native marker; original-scope inspection required",
                ),
                Some(journal),
                None,
            ));
        };
        // The marker supplies only a selector. Commit it before opening a
        // device, then require the same physical qualification as any Active row.
        if let Err(error) = journal.checkpoint_discovered(&intent, record) {
            return Err(fail(OpenStage::Checkpoint, error, Some(journal), None));
        }
    }
    let record = match journal.state().cloned() {
        Some(State::Empty) => return Ok(journal),
        Some(State::Active(record)) => record,
        _ => {
            return Err(fail(
                OpenStage::Recover,
                io::Error::other("checkpoint outcome is unknown"),
                Some(journal),
                None,
            ));
        }
    };
    if let Err(error) = journal.fence_active(&record) {
        return Err(fail(OpenStage::Recover, error, Some(journal), None));
    }
    let observed = match record.clone().recover() {
        Ok(observed) => observed,
        Err(error) => {
            return Err(fail(
                OpenStage::Recover,
                io::Error::other(error),
                Some(journal),
                None,
            ));
        }
    };
    let mut handle = match observed {
        Observation::Absent(_) => {
            if let Err(error) = journal.clear_active(&record) {
                return Err(fail(OpenStage::Checkpoint, error, Some(journal), None));
            }
            return Ok(journal);
        }
        Observation::Ready(cleanup) => cleanup.into_handle(),
    };
    if let Some(lease) = handle.interface.as_mut() {
        lease.checkpoint = Some(Box::new(journal));
    } else {
        let cleanup = handle.close().err();
        return Err(fail(
            OpenStage::Recover,
            io::Error::other("qualified TUN lost its retirement owner"),
            Some(journal),
            cleanup,
        ));
    }
    match handle.retire() {
        Ok(Some(journal)) => Ok(journal),
        Ok(None) => Err(fail(
            OpenStage::Recover,
            io::Error::other("retired TUN lost its original checkpoint lock"),
            None,
            None,
        )),
        Err(error) => Err(fail(OpenStage::Recover, error, None, None)),
    }
}
