//! Original local ownership capabilities; no serial is a wire/source authority.
use core::ptr;
#[derive(Debug)]
struct Brand {
    _address: u8,
}
/// Caller-owned lifetime domain. This value cannot be cloned or replaced while
/// a service or its original handles borrow it.
#[derive(Debug)]
pub struct Instance {
    brand: Brand,
}
impl Instance {
    /// Create a fresh address-distinct local ownership domain without native IO.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            brand: Brand { _address: 0 },
        }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
macro_rules! handle {
    ($name:ident,$description:literal) => {
        #[doc=$description]
        #[derive(Clone, Copy, Debug)]
        pub struct $name<'id> {
            brand: &'id Brand,
            serial: u64,
        }
        impl<'id> $name<'id> {
            /// Diagnostic serial only; equality also requires this original domain.
            #[must_use]
            pub const fn value(self) -> u64 {
                self.serial
            }
            pub(crate) fn new(instance: &'id Instance, serial: u64) -> Self {
                Self {
                    brand: &instance.brand,
                    serial,
                }
            }
            pub(crate) fn belongs(self, instance: &Instance) -> bool {
                ptr::eq(self.brand, &instance.brand)
            }
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                ptr::eq(self.brand, other.brand) && self.serial == other.serial
            }
        }
        impl Eq for $name<'_> {}
    };
}
handle!(
    Client,
    "One original admitted local client/source generation."
);
handle!(
    Operation,
    "One original committed set operation, independent of its raw request ID."
);
handle!(
    Incoming,
    "One original actual peer-channel offer before ownership adoption."
);
handle!(
    EffectId,
    "One original immutable output or retirement effect."
);
/// Actual peer channel ownership, retained through its original close debt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerOwner<'id> {
    /// Pending request offered on the original listener/channel.
    Incoming(Incoming<'id>),
    /// Committed operation after actual local AdoptPeer application.
    Operation(Operation<'id>),
}
