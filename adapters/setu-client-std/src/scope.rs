//! Non-ZST original client scopes, never encoded as private wire fields.
use gnunet_types::Error;
use std::sync::atomic::{AtomicU64, Ordering};
/// Stable caller-owned allocation domain for bounded dynamic native clients.
#[derive(Debug)]
pub struct Instance {
    allocations: AtomicU64,
}

impl Instance {
    /// Fresh client brand, without global counters or native effects.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allocations: AtomicU64::new(0),
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
        pub struct $name<'a> {
            owner: &'a Instance,
            allocation: u64,
            serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                core::ptr::eq(self.owner, other.owner)
                    && self.allocation == other.allocation
                    && self.serial == other.serial
            }
        }
        impl Eq for $name<'_> {}
        impl $name<'_> {
            /// Diagnostic serial, incapable of reconstructing original authority.
            #[must_use]
            pub const fn diagnostic(self) -> u64 {
                self.serial
            }
        }
    };
}
token!(
    Operation,
    "One original SETU operation; not a raw wire request id."
);
token!(
    Epoch,
    "One actually attached physical MQ of this original client."
);
token!(
    WriteId,
    "One immutable original native frame, including its exact original MQ."
);
pub(crate) struct Scope<'a> {
    owner: &'a Instance,
    allocation: u64,
    operation: u64,
    epoch: u64,
    write: u64,
}
impl<'a> Scope<'a> {
    pub(crate) fn new(instance: &'a Instance) -> Result<Self, Error> {
        let prior = instance
            .allocations
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                old.checked_add(1)
            })
            .map_err(|_| Error::Overflow)?;
        let allocation = prior.checked_add(1).ok_or(Error::Overflow)?;
        Ok(Self {
            owner: instance,
            allocation,
            operation: 0,
            epoch: 0,
            write: 0,
        })
    }
    pub(crate) fn operation(&mut self) -> Result<Operation<'a>, Error> {
        self.operation = self.operation.checked_add(1).ok_or(Error::Overflow)?;
        Ok(Operation {
            owner: self.owner,
            allocation: self.allocation,
            serial: self.operation,
        })
    }
    pub(crate) fn epoch(&mut self) -> Result<Epoch<'a>, Error> {
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Overflow)?;
        Ok(Epoch {
            owner: self.owner,
            allocation: self.allocation,
            serial: self.epoch,
        })
    }
    pub(crate) fn write(&mut self) -> Result<WriteId<'a>, Error> {
        self.write = self.write.checked_add(1).ok_or(Error::Overflow)?;
        Ok(WriteId {
            owner: self.owner,
            allocation: self.allocation,
            serial: self.write,
        })
    }
    pub(crate) fn owns(&self, operation: Operation<'_>) -> bool {
        core::ptr::eq(self.owner, operation.owner) && self.allocation == operation.allocation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure allocation identity assertions with checked counter setup"
    )]
    fn reconstructed_scopes_cannot_adopt_old_tokens() -> Result<(), Error> {
        let instance = Instance::new();
        let mut first = Scope::new(&instance)?;
        let operation = first.operation()?;
        let epoch = first.epoch()?;
        let write = first.write()?;
        let mut replacement = Scope::new(&instance)?;
        let new_operation = replacement.operation()?;
        assert_eq!(operation.diagnostic(), new_operation.diagnostic());
        assert_ne!(operation, new_operation);
        assert_ne!(epoch, replacement.epoch()?);
        assert_ne!(write, replacement.write()?);
        assert!(first.owns(operation));
        assert!(!replacement.owns(operation));
        let other = Instance::new();
        assert!(!Scope::new(&other)?.owns(operation));
        instance.allocations.store(u64::MAX, Ordering::Relaxed);
        assert!(matches!(Scope::new(&instance), Err(Error::Overflow)));
        assert_eq!(instance.allocations.load(Ordering::Relaxed), u64::MAX);
        Ok(())
    }
}
