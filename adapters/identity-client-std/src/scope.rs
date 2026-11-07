use gnunet_types::Error;
use std::sync::atomic::{AtomicU64, Ordering};
/// Stable caller-owned allocation domain, reusable by bounded dynamic clients.
/// Checked unique IDs are private Rust metadata and never enter official wire.
#[derive(Debug, Default)]
pub struct Instance {
    next: AtomicU64,
}
impl Instance {
    /// Fresh domain. No key/clock/native operation occurs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
        }
    }
    fn allocate(&self) -> Result<u64, Error> {
        self.next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map(|old| old + 1)
            .map_err(|_| Error::Overflow)
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Scope<'id> {
    pub domain: &'id Instance,
    pub owner: u64,
}
impl<'id> Scope<'id> {
    pub fn new(domain: &'id Instance) -> Result<Self, Error> {
        Ok(Self {
            domain,
            owner: domain.allocate()?,
        })
    }
    pub fn epoch(self) -> Result<Epoch<'id>, Error> {
        Ok(Epoch {
            scope: self,
            serial: self.domain.allocate()?,
        })
    }
    pub fn operation(self) -> Result<Operation<'id>, Error> {
        Ok(Operation {
            scope: self,
            serial: self.domain.allocate()?,
        })
    }
    pub fn ego(self, epoch: Epoch<'id>) -> Result<Ego<'id>, Error> {
        Ok(Ego {
            scope: self,
            epoch,
            serial: self.domain.allocate()?,
        })
    }
    pub fn same(self, other: Self) -> bool {
        core::ptr::eq(self.domain, other.domain) && self.owner == other.owner
    }
}
macro_rules! token {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy)]
        pub struct $name<'id> {
            pub(crate) scope: Scope<'id>,
            pub(crate) serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                self.scope.same(other.scope) && self.serial == other.serial
            }
        }
        impl Eq for $name<'_> {}
        impl std::fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("allocation", &self.serial)
                    .finish_non_exhaustive()
            }
        }
        impl $name<'_> {
            /// Original diagnostic allocation, not a wire RID or authority constructor.
            #[must_use]
            pub const fn diagnostic(self) -> u64 {
                self.serial
            }
        }
    };
}
token!(Epoch, "Original actually attached physical IDENTITY MQ.");
token!(Operation, "Original bounded FIFO IDENTITY operation.");
/// One current monitor ego. Rename preserves it; deletion/source loss revokes it.
#[derive(Clone, Copy)]
pub struct Ego<'id> {
    pub(crate) scope: Scope<'id>,
    pub(crate) epoch: Epoch<'id>,
    pub(crate) serial: u64,
}
impl PartialEq for Ego<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.scope.same(other.scope) && self.epoch == other.epoch && self.serial == other.serial
    }
}
impl Eq for Ego<'_> {}
impl std::fmt::Debug for Ego<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ego")
            .field("allocation", &self.serial)
            .field("source", &self.epoch)
            .finish_non_exhaustive()
    }
}
impl<'id> Ego<'id> {
    /// Exact original monitor source.
    #[must_use]
    pub const fn epoch(self) -> Epoch<'id> {
        self.epoch
    }
    /// Local diagnostic allocation, never derived by hashing private material.
    #[must_use]
    pub const fn diagnostic(self) -> u64 {
        self.serial
    }
}
