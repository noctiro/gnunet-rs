//! Stable allocation-free authority shared by the two STATISTICS owner APIs.
use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};
/// Caller-owned, non-zero-sized identity storage for one STATISTICS owner.
/// Construction exclusively borrows this value. Neither the owner nor any issued
/// token may outlive it or permit another owner to reuse it concurrently.
/// The address is local metadata and never appears on the GNUnet wire.
///
/// One identity cannot construct two simultaneous owners, even when their local
/// counters would be equal.
/// ```compile_fail,E0499
/// use gnunet_client::statistics_handle::{Instance,StatisticsHandle};
/// let mut instance=Instance::new();
/// let a=StatisticsHandle::<2,32,1,4,2>::new(&mut instance,b"a",true).unwrap().unwrap();
/// let b=StatisticsHandle::<2,32,1,4,2>::new(&mut instance,b"b",true).unwrap().unwrap();
/// drop((a,b));
/// ```
/// Issued authority cannot survive the caller's identity storage.
/// ```compile_fail,E0597
/// use gnunet_client::{statistics::Selector,statistics_handle::{Instance,StatisticsHandle}};
/// let id={
///     let mut instance=Instance::new();
///     let mut owner=StatisticsHandle::<2,32,1,4,2>::new(&mut instance,b"a",true).unwrap().unwrap();
///     owner.get(Selector{subsystem:b"a",name:b"n"}).unwrap()
/// };
/// std::hint::black_box(id);
/// ```
#[derive(Debug)]
pub struct Instance {
    _marker: u8,
}
impl Instance {
    /// Create unused identity storage; no allocation, atomic or global is used.
    #[must_use]
    pub const fn new() -> Self {
        Self { _marker: 0 }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Brand<'a>(&'a Instance);
impl<'a> Brand<'a> {
    pub(crate) const fn new(instance: &'a Instance) -> Self {
        Self(instance)
    }
}
impl PartialEq for Brand<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.0, other.0)
    }
}
impl Eq for Brand<'_> {}
impl Hash for Brand<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        core::ptr::hash(core::ptr::from_ref(self.0), state);
    }
}
impl PartialOrd for Brand<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Brand<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        core::ptr::from_ref(self.0)
            .addr()
            .cmp(&core::ptr::from_ref(other.0).addr())
    }
}
