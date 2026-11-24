//! Storage for bounded names shared by queued STATISTICS actions.
use gnunet_types::Error;

/// Name storage for a STATISTICS owner. Only the built-in storage types
/// implement this trait; the owner's selector and frame limits apply to both.
pub trait NameStorage: private::Sealed + AsRef<[u8]> + Clone {
    #[doc(hidden)]
    fn copy_parts(parts: &[&[u8]]) -> Result<Self, Error>;
}

mod private {
    pub trait Sealed {}
    impl<const N: usize> Sealed for super::InlineNames<N> {}
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    impl Sealed for super::HeapNames {}
}

/// Fixed inline storage for the allocation-free STATISTICS owner.
#[derive(Clone)]
pub struct InlineNames<const N: usize>([u8; N]);

impl<const N: usize> AsRef<[u8]> for InlineNames<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> NameStorage for InlineNames<N> {
    fn copy_parts(parts: &[&[u8]]) -> Result<Self, Error> {
        let mut bytes = [0; N];
        let mut remaining = bytes.as_mut_slice();
        for part in parts {
            let (output, rest) = remaining
                .split_at_mut_checked(part.len())
                .ok_or(Error::Capacity)?;
            output.copy_from_slice(part);
            remaining = rest;
        }
        Ok(Self(bytes))
    }
}

/// Heap storage for hosted owners. Allocates only the bytes actually used.
/// A queued WATCH shares the original names, including after cancellation.
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
#[derive(Clone)]
pub struct HeapNames(alloc::sync::Arc<alloc::vec::Vec<u8>>);

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl AsRef<[u8]> for HeapNames {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl NameStorage for HeapNames {
    fn copy_parts(parts: &[&[u8]]) -> Result<Self, Error> {
        let len = parts.iter().try_fold(0usize, |len, part| {
            len.checked_add(part.len()).ok_or(Error::Overflow)
        })?;
        let mut bytes = alloc::vec::Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
        for part in parts {
            bytes.extend_from_slice(part);
        }
        Ok(Self(alloc::sync::Arc::new(bytes)))
    }
}
