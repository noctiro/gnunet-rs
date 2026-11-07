use core::{fmt, ptr};

/// Caller-owned, allocation-free identity for one PILS client lifetime.
///
/// Each client exclusively borrows distinct nonzero-sized storage. Moving the
/// client is safe; operation capabilities cannot outlive or share this owner.
///
/// ```compile_fail
/// use gnunet_pils::{client::{Client, Instance}, HelloLimits, Profile};
/// let mut instance = Instance::new();
/// let limits = HelloLimits { maximum_input_bytes: 4096, maximum_address_bytes: 2048, maximum_addresses: 32 };
/// let a = Client::<8, 1024, 4096>::new(&mut instance, Profile::Reference029, limits).unwrap();
/// let b = Client::<8, 1024, 4096>::new(&mut instance, Profile::Reference029, limits).unwrap();
/// drop((a, b));
/// ```
///
/// ```compile_fail
/// use gnunet_pils::{client::{Client, Instance, KeyTarget}, HelloLimits, Profile};
/// let token;
/// {
///     let mut instance = Instance::new();
///     let limits = HelloLimits { maximum_input_bytes: 4096, maximum_address_bytes: 2048, maximum_addresses: 32 };
///     let mut owner = Client::<8, 1024, 4096>::new(&mut instance, Profile::Reference029, limits).unwrap();
///     token = owner.ecdh([7; 32], KeyTarget::ServiceCurrent).unwrap();
/// }
/// let _numeric = token.value();
/// ```
#[derive(Default)]
pub struct Instance {
    marker: u8,
}
impl Instance {
    /// Reserve a distinct owner identity without allocation or global counters.
    #[must_use]
    pub const fn new() -> Self {
        Self { marker: 0 }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Brand<'a>(&'a Instance);
impl<'a> Brand<'a> {
    pub(super) fn new(instance: &'a mut Instance) -> Self {
        Self(instance)
    }
}
impl PartialEq for Brand<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.0, other.0)
    }
}
impl Eq for Brand<'_> {}
impl fmt::Debug for Brand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The byte establishes real owner storage; it never carries authority.
        let _marker = self.0.marker;
        f.write_str("Instance")
    }
}
/// One logical operation, scoped to its original client. Its value is diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationId<'a> {
    pub(super) serial: u64,
    pub(super) brand: Brand<'a>,
}
impl OperationId<'_> {
    /// Local diagnostic number; it is not necessarily an on-wire request number.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}
/// One original physical MQ lifetime. It is never encoded on the official wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Epoch<'a> {
    pub(super) serial: u64,
    pub(super) brand: Brand<'a>,
}
impl Epoch<'_> {
    /// Diagnostic generation; numeric equality alone grants no authority.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}
/// One original copied output frame. Cancellation does not revoke its byte lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitId<'a> {
    pub(super) serial: u64,
    pub(super) epoch: Epoch<'a>,
}
impl TransmitId<'_> {
    /// Local diagnostic number, never an acknowledgement from the service.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}
