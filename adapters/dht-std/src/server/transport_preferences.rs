//! Connection-local TRANSPORT requests; desired CORE peers own no MQ receipt.
use gnunet_types::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Change {
    epoch: u64,
    pub peer: [u8; 32],
    pub cancel: bool,
}

/// Only metadata for requests admitted to the one actual application MQ.
/// A retired MQ removes its requests itself; its cancels never cross epochs.
pub(super) struct Preferences {
    epoch: Option<u64>,
    last_epoch: u64,
    registered: Vec<[u8; 32]>,
    maximum: usize,
    pending: Option<Change>,
}
impl Preferences {
    pub fn new(maximum: usize) -> Result<Self, Error> {
        let mut registered = Vec::new();
        registered
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            epoch: None,
            last_epoch: 0,
            registered,
            maximum,
            pending: None,
        })
    }
    pub fn attached(&mut self, epoch: u64) -> Result<(), Error> {
        if epoch == 0
            || epoch <= self.last_epoch
            || self.epoch.is_some()
            || !self.registered.is_empty()
            || self.pending.is_some()
        {
            return Err(Error::StaleGeneration);
        }
        self.epoch = Some(epoch);
        self.last_epoch = epoch;
        Ok(())
    }
    pub fn retired(&mut self, epoch: u64) -> Result<(), Error> {
        if self.epoch.unwrap_or(self.last_epoch) != epoch {
            return Err(Error::StaleGeneration);
        }
        self.epoch = None;
        self.registered.clear();
        self.pending = None;
        Ok(())
    }
    pub fn next(&self, desired: impl Iterator<Item = [u8; 32]> + Clone) -> Option<Change> {
        let epoch = self.epoch?;
        if self.pending.is_some() {
            return None;
        }
        // Old registrations consume the same bound as live ones. Drain these
        // before admitting another peer; churn never grows a cancellation list.
        for peer in &self.registered {
            if !desired.clone().any(|current| current == *peer) {
                return Some(Change {
                    epoch,
                    peer: *peer,
                    cancel: true,
                });
            }
        }
        for peer in desired {
            if !self.registered.contains(&peer) {
                if self.registered.len() == self.maximum {
                    return None;
                }
                return Some(Change {
                    epoch,
                    peer,
                    cancel: false,
                });
            }
        }
        None
    }
    /// Called only after the actual original Application admitted this frame.
    /// Retain the registration already during a positive partial write, so a
    /// peer loss cannot discard the debt before that frame settles.
    pub fn admitted(&mut self, change: Change) -> Result<(), Error> {
        if self.epoch != Some(change.epoch) || self.pending.is_some() {
            return Err(Error::StaleGeneration);
        }
        let contains = self.registered.contains(&change.peer);
        if change.cancel {
            if !contains {
                return Err(Error::NotFound);
            }
        } else {
            if contains {
                return Err(Error::Conflict);
            }
            if self.registered.len() == self.maximum {
                return Err(Error::Capacity);
            }
            self.registered.push(change.peer);
        }
        self.pending = Some(change);
        Ok(())
    }
    pub fn written(&mut self, epoch: u64) -> Result<(), Error> {
        if self.epoch != Some(epoch) {
            return Err(Error::StaleGeneration);
        }
        // A normal address hint shares the same Application but is not a peer
        // registration. It cannot create or remove preference ownership.
        if let Some(change) = self.pending.take() {
            if change.epoch != epoch {
                return Err(Error::StaleGeneration);
            }
            if change.cancel {
                let index = self
                    .registered
                    .iter()
                    .position(|peer| *peer == change.peer)
                    .ok_or(Error::NotFound)?;
                self.registered.remove(index);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
