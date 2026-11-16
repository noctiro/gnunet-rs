//! One original locked checkpoint with two bounded, checksummed state frames.
mod files;
mod frame;
#[cfg(test)]
mod tests;
use super::Record;
use files::Files;
use frame::Frame;
use std::{io, path::Path};

/// Durable pre-allocation correlation. A pending intent never authorizes a new
/// allocation or destruction based solely on its requested name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Intent {
    pub(crate) nonce: [u8; 32],
    requested: [u8; 16],
}
impl Intent {
    #[cfg(test)]
    pub(crate) fn for_marker_test(nonce: [u8; 32]) -> Self {
        Self {
            nonce,
            requested: [0; 16],
        }
    }

    /// Original requested interface name, or None for a kernel-selected name.
    ///
    /// # Errors
    /// Refuses a malformed internal name rather than normalizing it.
    pub fn requested_name(&self) -> io::Result<Option<&str>> {
        if self.requested == [0; 16] {
            Ok(None)
        } else {
            super::read_name(&self.requested).map(Some)
        }
    }
    #[cfg(any(target_os = "freebsd", test))]
    fn matches(&self, record: &Record) -> io::Result<bool> {
        Ok(self.nonce == record.birth
            && self
                .requested_name()?
                .is_none_or(|name| record.interface_name().is_ok_and(|actual| actual == name)))
    }
}
/// Latest confirmed checkpoint state. An intent fences a possibly dispatched
/// allocation; an active record still requires physical native qualification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum State {
    /// No outstanding allocation tracked by this checkpoint.
    Empty,
    /// Creation was admitted and may have been dispatched; full identity is
    /// not checkpointed. This does not assert that an interface was created.
    Creating(Intent),
    /// A complete native selector is checkpointed. Physical cleanup ownership
    /// and packet readiness require their separate native qualification.
    Active(Record),
}
/// Original private checkpoint and native exclusive file lock. The parent must
/// already exist as a private directory. The file remains in place across
/// updates and Drop; no copied identity is used as a file capability.
#[derive(Debug)]
pub struct Journal {
    files: Files,
    confirmed: Frame,
    slot: usize,
    floor: u64,
    known: bool,
}
#[cfg(any(target_os = "freebsd", test))]
fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
impl Journal {
    /// Open/create and lock the actual private checkpoint, synchronizing a new
    /// image and its directory entry before returning. Existing corrupt or
    /// incomplete images are refused without overwriting them.
    ///
    /// # Errors
    /// Preserves private-owner, namespace, native-lock, I/O and format errors.
    pub fn open(path: &Path) -> io::Result<Self> {
        let (mut files, created) = Files::open(path)?;
        let (confirmed, slot) = if created {
            let frame = Frame {
                sequence: 0,
                state: State::Empty,
            };
            files.initialize(&frame)?;
            (frame, 0)
        } else {
            files.read()?
        };
        files.sync()?;
        files.sync_name()?;
        let floor = confirmed.sequence;
        Ok(Self {
            files,
            confirmed,
            slot,
            floor,
            known: true,
        })
    }
    /// Latest confirmed state. None means a write/sync outcome is unknown;
    /// callers must reconcile before admitting more native work.
    #[must_use]
    pub fn state(&self) -> Option<&State> {
        self.known.then_some(&self.confirmed.state)
    }
    /// Re-read and synchronize this same original checkpoint. This neither
    /// allocates nor destroys an interface, and never clears an allocation intent.
    ///
    /// # Errors
    /// Refuses substituted/ambiguous images and preserves read/sync failures.
    pub fn reconcile(&mut self) -> io::Result<&State> {
        self.known = false;
        let (frame, slot) = self.files.read()?;
        self.files.sync()?;
        self.floor = self.floor.max(frame.sequence);
        self.confirmed = frame;
        self.slot = slot;
        self.known = true;
        Ok(&self.confirmed.state)
    }
    #[cfg(any(target_os = "freebsd", test))]
    fn update(&mut self, state: State) -> io::Result<()> {
        self.fence()?;
        let sequence = self
            .floor
            .checked_add(1)
            .ok_or_else(|| refused("TUN checkpoint sequence exhausted"))?;
        self.floor = sequence;
        let frame = Frame { sequence, state };
        let slot = 1 - self.slot;
        self.known = false;
        self.files.write(slot, &frame)?;
        let (observed, selected) = self.files.read()?;
        if observed != frame || selected != slot {
            return Err(refused(
                "TUN checkpoint write did not select its original frame",
            ));
        }
        self.confirmed = frame;
        self.slot = slot;
        self.known = true;
        Ok(())
    }
    #[cfg(any(target_os = "freebsd", test))]
    fn fence(&mut self) -> io::Result<()> {
        if !self.known {
            return Err(refused(
                "TUN checkpoint outcome is unknown; reconcile required",
            ));
        }
        let (frame, slot) = self.files.read()?;
        if frame != self.confirmed || slot != self.slot {
            return Err(refused("original TUN checkpoint changed outside its owner"));
        }
        Ok(())
    }
    #[cfg(any(target_os = "freebsd", test))]
    pub(crate) fn begin(&mut self, requested: Option<&str>) -> io::Result<Intent> {
        if self.state() != Some(&State::Empty) {
            return Err(refused("TUN checkpoint has an outstanding allocation"));
        }
        let mut name = [0; 16];
        if let Some(requested) = requested {
            if requested.is_empty() || requested.len() >= name.len() || requested.contains('\0') {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            name[..requested.len()].copy_from_slice(requested.as_bytes());
        }
        let mut nonce = [0; 32];
        gnunet_native::entropy::fill(&mut nonce)?;
        if nonce == [0; 32] {
            return Err(refused("zero TUN allocation correlation marker"));
        }
        let intent = Intent {
            nonce,
            requested: name,
        };
        self.update(State::Creating(intent.clone()))?;
        Ok(intent)
    }
    #[cfg(any(target_os = "freebsd", test))]
    pub(crate) fn activate(&mut self, record: Record) -> io::Result<()> {
        match self.state() {
            Some(State::Creating(intent)) if intent.matches(&record)? => {}
            _ => {
                return Err(refused(
                    "TUN identity differs from its admitted allocation intent",
                ));
            }
        }
        self.update(State::Active(record))
    }
    #[cfg(any(target_os = "freebsd", test))]
    pub(crate) fn checkpoint_discovered(
        &mut self,
        intent: &Intent,
        record: Record,
    ) -> io::Result<()> {
        if !matches!(self.state(), Some(State::Creating(actual)) if actual == intent)
            || record.birth != intent.nonce
        {
            return Err(refused(
                "discovered TUN does not match its original allocation intent",
            ));
        }
        self.update(State::Active(record))
    }
    #[cfg(any(target_os = "freebsd", test))]
    pub(crate) fn fence_intent(&mut self, intent: &Intent) -> io::Result<()> {
        self.fence()?;
        if !matches!(self.state(), Some(State::Creating(actual)) if actual == intent) {
            return Err(refused(
                "TUN checkpoint changed its original allocation intent",
            ));
        }
        Ok(())
    }
    #[cfg(any(target_os = "freebsd", test))]
    pub(crate) fn fence_active(&mut self, record: &Record) -> io::Result<()> {
        self.fence()?;
        if !matches!(self.state(), Some(State::Active(actual)) if actual == record) {
            return Err(refused("TUN checkpoint does not own this active selector"));
        }
        Ok(())
    }
    #[cfg(any(target_os = "freebsd", test))]
    pub(crate) fn clear_active(&mut self, record: &Record) -> io::Result<()> {
        self.fence_active(record)?;
        self.update(State::Empty)
    }
    #[cfg(any(target_os = "freebsd", test))]
    pub(crate) fn finish_active(&mut self, record: &Record) -> io::Result<()> {
        match self.state() {
            Some(State::Empty) => self.fence(),
            Some(State::Active(actual)) if actual == record => self.clear_active(record),
            _ => Err(refused(
                "TUN cleanup checkpoint must be reconciled before retirement",
            )),
        }
    }
    #[cfg(any(target_os = "freebsd", test))]
    pub(crate) fn finish_failed_creation(
        &mut self,
        intent: &Intent,
        record: Option<&Record>,
    ) -> io::Result<()> {
        if !self.known {
            self.reconcile()?;
        }
        match self.state().cloned() {
            Some(State::Empty) => self.fence(),
            Some(State::Creating(actual)) if &actual == intent => self.abort(intent),
            Some(State::Active(actual)) if Some(&actual) == record => self.clear_active(&actual),
            _ => Err(refused("TUN cleanup cannot clear a different allocation")),
        }
    }
    #[cfg(any(target_os = "freebsd", test))]
    pub(crate) fn abort(&mut self, intent: &Intent) -> io::Result<()> {
        if !matches!(self.state(), Some(State::Creating(actual)) if actual == intent) {
            return Err(refused(
                "TUN checkpoint does not own this allocation intent",
            ));
        }
        self.update(State::Empty)
    }
}
