//! Original non-forgeable native job and physical source identities.
use gnunet_types::Error;
use std::sync::atomic::{AtomicU64, Ordering};
/// Shared caller-owned identity storage. Construction has no native effects.
#[derive(Debug)]
pub struct Instance {
    next: AtomicU64,
}
impl Instance {
    /// Fresh stable domain for bounded slots and repeated independent jobs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
        }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
macro_rules! token {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug)]
        pub struct $name<'id> {
            owner: &'id Instance,
            serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                core::ptr::eq(self.owner, other.owner) && self.serial == other.serial
            }
        }
        impl Eq for $name<'_> {}
        impl $name<'_> {
            /// Diagnostic serial alone cannot reconstruct original authority.
            #[must_use]
            pub const fn diagnostic(self) -> u64 {
                self.serial
            }
        }
    };
}
token!(Job, "One original REGEX search or announcement intent.");
token!(Epoch, "One actually attached original REGEX MQ.");
token!(WriteId, "One immutable original REGEX request write.");
pub(crate) struct Scope<'id> {
    owner: &'id Instance,
    allocation: u64,
    physical: u64,
    next_physical: Option<u64>,
}
impl<'id> Scope<'id> {
    pub(crate) fn new(owner: &'id Instance) -> Result<Self, Error> {
        let previous = owner
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Overflow)?;
        Ok(Self {
            owner,
            allocation: previous + 1,
            physical: 0,
            next_physical: None,
        })
    }
    pub(crate) fn job(&self) -> Job<'id> {
        Job {
            owner: self.owner,
            serial: self.allocation,
        }
    }
    pub(crate) fn write(&self) -> WriteId<'id> {
        WriteId {
            owner: self.owner,
            serial: self.physical,
        }
    }
    pub(crate) fn attachment(&mut self) -> Result<Epoch<'id>, Error> {
        let serial = if let Some(serial) = self.next_physical {
            serial
        } else {
            let previous = self
                .owner
                .next
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| Error::Overflow)?;
            let serial = previous + 1;
            self.next_physical = Some(serial);
            serial
        };
        Ok(Epoch {
            owner: self.owner,
            serial,
        })
    }
    pub(crate) fn attached(&mut self, epoch: Epoch<'id>) {
        // The caller reserved this private token before the real connect poll.
        self.physical = epoch.serial;
        self.next_physical = None;
    }
}
