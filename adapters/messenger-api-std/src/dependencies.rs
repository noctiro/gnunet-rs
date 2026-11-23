//! Required causal/control retrieval is protocol progress, independently of a
//! caller's optional history traversal. Every GET owns its original source and
//! one fixed admitted lifetime; absence does not cause an automatic retry.
mod history;

pub(crate) use history::Fetch;

use crate::{clock::Span, types::Intent, *};
use gnunet_types::Error as Fault;

impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    pub(crate) fn drive_dependencies(&mut self, index: usize, now: u64) -> Result<(), Error> {
        if !self.protocol_available(Intent::Dependency)
            || self.rooms[index].close_after.is_some()
            || !self.frontier_get_ready(index)?
        {
            return Ok(());
        }
        let room = self.rooms[index].room;
        let Some(source) = self.rooms[index].source else {
            return Ok(());
        };
        let Some((hash, original)) = self
            .core
            .pending_dependencies(room)?
            .find(|(_, original)| *original == source)
        else {
            return Ok(());
        };
        let (_, checked, _) = self.live_source(room)?;
        if checked != original {
            return Err(Fault::StaleGeneration.into());
        }
        self.next_job.checked_add(1).ok_or(Fault::Overflow)?;
        let span = Span::new(now, self.limits.operation_lifetime)?;
        match self.admit_history_get(index, hash, span, now, Intent::Dependency) {
            Ok(_) => {}
            // A caller may already own the same GET. Its original operation
            // keeps the native response and deadline; no replacement is made.
            Err(
                Error::Domain(domain::Error::Protocol(Fault::WouldBlock | Fault::Capacity))
                | Error::Local(Fault::WouldBlock | Fault::Capacity),
            ) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

/// Called only after the native source or its acknowledged room lease stopped.
/// Retiring these logical requirements does not cancel an original GET job;
/// those jobs retain their separate stopped/terminal ownership and reporting.
pub(crate) fn retire_stopped<'a>(
    core: &mut domain::Core<'a>,
    room: Room<'a>,
    source: Source<'a>,
) -> Result<(), domain::Error> {
    loop {
        let next = core
            .missing_messages(room)?
            .find_map(|(hash, original, _)| (original == source).then_some(hash));
        let Some(hash) = next else {
            return Ok(());
        };
        core.retire_missing(room, &hash, source)?;
    }
}
