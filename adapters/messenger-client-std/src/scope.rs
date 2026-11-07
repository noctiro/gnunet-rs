use gnunet_types::Error;
use std::sync::atomic::{AtomicU64, Ordering};
/// Caller-owned allocation domain. Diagnostic serials are never wire fields.
#[derive(Debug, Default)]
pub struct Instance {
    next: AtomicU64,
}
impl Instance {
    /// Create no native/clock/key work.
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
pub(crate) struct Scope<'a> {
    domain: &'a Instance,
    owner: u64,
}
impl<'a> Scope<'a> {
    pub fn new(domain: &'a Instance) -> Result<Self, Error> {
        Ok(Self {
            domain,
            owner: domain.allocate()?,
        })
    }
    pub fn same(self, other: Self) -> bool {
        core::ptr::eq(self.domain, other.domain) && self.owner == other.owner
    }
    pub fn epoch(self) -> Result<Epoch<'a>, Error> {
        Ok(Epoch {
            scope: self,
            serial: self.domain.allocate()?,
        })
    }
    pub fn operation(self) -> Result<Operation<'a>, Error> {
        Ok(Operation {
            scope: self,
            serial: self.domain.allocate()?,
        })
    }
}
macro_rules! token {
    ($name:ident, $doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy)]
        pub struct $name<'a> {
            pub(crate) scope: Scope<'a>,
            serial: u64,
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
            /// Diagnostic only: no wire RID, remote identity or constructor.
            pub const fn diagnostic(self) -> u64 {
                self.serial
            }
        }
    };
}
token!(
    Epoch,
    "One original actually attached MESSENGER physical MQ."
);
token!(
    Operation,
    "One original immutable local MESSENGER frame submission."
);
