use core::{fmt, ptr};
/// Caller-owned nonzero-sized original instance. Tokens borrow it exclusively
/// through a live client; moving the client does not change this identity.
///
/// ```compile_fail
/// use gnunet_dht_client::{Client,Instance,Limits};
/// let mut instance=Instance::new();
/// let mut first=Client::new(&mut instance,Limits::default()).unwrap();
/// let old=first.connect().unwrap();
/// drop(first);
/// let mut next=Client::new(&mut instance,Limits::default()).unwrap();
/// next.lost(old).unwrap();
/// ```
pub struct Instance {
    _nonzero: u8,
}
impl Instance {
    /// Allocate identity storage without runtime/global ID allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self { _nonzero: 0 }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Brand<'a>(pub(crate) &'a Instance);
impl PartialEq for Brand<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.0, other.0)
    }
}
impl Eq for Brand<'_> {}
impl fmt::Debug for Brand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalDhtClient")
    }
}
macro_rules! id {
    ($name:ident, $doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name<'a> {
            pub(crate) brand: Brand<'a>,
            pub(crate) serial: u64,
        }
        impl $name<'_> {
            /// Diagnostic serial only; it cannot reconstruct this capability.
            #[must_use]
            pub const fn diagnostic(self) -> u64 {
                self.serial
            }
        }
    };
}
id!(
    Epoch,
    "Original physical DHT MQ, independent of logical GET lifetimes."
);
id!(
    GetId,
    "Original logical GET identity, not its opaque eight wire bytes."
);
id!(MonitorId, "Original logical monitor registration.");
id!(
    HelloId,
    "Original logical request for a public HELLO observation."
);
id!(
    OperationId,
    "Original one-shot PUT or HELLO-offer operation."
);
id!(
    AttemptId,
    "Original immutable local wire attempt; only full local writing settles it."
);
