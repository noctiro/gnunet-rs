//! Non-ZST original client scopes, never encoded as private wire fields.
use gnunet_types::Error;
/// Exclusively borrowed identity storage for one original native client.
#[derive(Debug)]
pub struct Instance {
    _private: u8,
}
impl Instance {
    /// Fresh client brand, without global counters or native effects.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: 0 }
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
            serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                core::ptr::eq(self.owner, other.owner) && self.serial == other.serial
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
    "One original VPN allocation intent; not a raw wire RID."
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
    operation: u64,
    epoch: u64,
    write: u64,
}
impl<'a> Scope<'a> {
    pub(crate) fn new(instance: &'a mut Instance) -> Self {
        Self {
            owner: instance,
            operation: 0,
            epoch: 0,
            write: 0,
        }
    }
    pub(crate) fn operation(&mut self) -> Result<Operation<'a>, Error> {
        self.operation = self.operation.checked_add(1).ok_or(Error::Overflow)?;
        Ok(Operation {
            owner: self.owner,
            serial: self.operation,
        })
    }
    pub(crate) fn epoch(&mut self) -> Result<Epoch<'a>, Error> {
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Overflow)?;
        Ok(Epoch {
            owner: self.owner,
            serial: self.epoch,
        })
    }
    pub(crate) fn write(&mut self) -> Result<WriteId<'a>, Error> {
        self.write = self.write.checked_add(1).ok_or(Error::Overflow)?;
        Ok(WriteId {
            owner: self.owner,
            serial: self.write,
        })
    }
    pub(crate) fn owns(&self, operation: Operation<'_>) -> bool {
        core::ptr::eq(self.owner, operation.owner)
    }
}
