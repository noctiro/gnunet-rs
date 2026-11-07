//! Fully checked concatenated objects. No list count or host pointer is serialized.
use crate::{Attribute, Credential, Presentation};
use core::{fmt, marker::PhantomData};
use gnunet_types::Error;

/// Independent finite byte and item limits for validation/iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListLimits {
    /// Maximum serialized bytes, including every object prefix.
    pub bytes: usize,
    /// Maximum complete objects. Trailing garbage is always an error.
    pub items: usize,
}
impl ListLimits {
    /// No RECLAIM IPC body can exceed the official BE16 total frame bound.
    pub const IPC: Self = Self {
        bytes: u16::MAX as usize,
        items: 1365,
    };
}
mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::Attribute<'_> {}
    impl Sealed for crate::Credential<'_> {}
    impl Sealed for crate::Presentation<'_> {}
}
/// The three supported self-delimiting RECLAIM object serializations.
/// Sealed so validated lists cannot acquire a zero-length/nonprogressing decoder.
pub trait Serialized<'a>: sealed::Sealed + Sized {
    /// Decode the next object and its positive byte count.
    fn decode_prefix(bytes: &'a [u8]) -> Result<(Self, usize), Error>;
    /// Complete serialized size after field validation.
    fn encoded_len(&self) -> Result<usize, Error>;
    /// Encode in caller-owned storage.
    fn encode(&self, out: &mut [u8]) -> Result<usize, Error>;
}
macro_rules! serialized {
    ($t:ident) => {
        impl<'a> Serialized<'a> for $t<'a> {
            fn decode_prefix(b: &'a [u8]) -> Result<(Self, usize), Error> {
                Self::decode_prefix(b)
            }
            fn encoded_len(&self) -> Result<usize, Error> {
                (*self).encoded_len()
            }
            fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
                (*self).encode(out)
            }
        }
    };
}
serialized!(Attribute);
serialized!(Credential);
serialized!(Presentation);

/// Validated immutable borrowed list. Empty lists are exactly zero bytes;
/// decoding validates all objects and consumes ALL bytes before returning.
pub struct List<'a, T> {
    bytes: &'a [u8],
    count: usize,
    marker: PhantomData<T>,
}
impl<T> Copy for List<'_, T> {}
impl<T> Clone for List<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> fmt::Debug for List<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("List")
            .field("items", &self.count)
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
impl<'a, T: Serialized<'a>> List<'a, T> {
    /// Validate within explicit caller limits; failure returns no partial list.
    pub fn new(bytes: &'a [u8], limits: ListLimits) -> Result<Self, Error> {
        if bytes.len() > limits.bytes {
            return Err(Error::Capacity);
        }
        let mut rest = bytes;
        let mut count = 0usize;
        while !rest.is_empty() {
            if count == limits.items {
                return Err(Error::Capacity);
            }
            let (_, used) = T::decode_prefix(rest)?;
            rest = rest.get(used..).ok_or(Error::Malformed)?;
            count = count.checked_add(1).ok_or(Error::Overflow)?;
        }
        Ok(Self {
            bytes,
            count,
            marker: PhantomData,
        })
    }
    /// The exact empty list, with no hidden sentinel or list-entry metadata.
    pub const fn empty() -> Self {
        Self {
            bytes: &[],
            count: 0,
            marker: PhantomData,
        }
    }
    /// Borrow original sensitive serialization explicitly.
    pub const fn expose_serialized(self) -> &'a [u8] {
        self.bytes
    }
    /// Number of complete objects, checked once at construction.
    pub const fn len(self) -> usize {
        self.count
    }
    /// Whether there are no objects.
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }
    /// Required bytes. No allocation occurs during this query or iteration.
    pub const fn encoded_len(self) -> usize {
        self.bytes.len()
    }
    /// Copy exactly the checked serialization after capacity preflight.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let out = out.get_mut(..self.bytes.len()).ok_or(Error::Capacity)?;
        out.copy_from_slice(self.bytes);
        Ok(self.bytes.len())
    }
    /// Borrowed immutable iteration with an exact finite upper bound.
    pub fn iter(self) -> Iter<'a, T> {
        Iter {
            rest: self.bytes,
            left: self.count,
            marker: PhantomData,
        }
    }
}
/// A list of attributes, without a count prefix or host linked-list pointers.
pub type AttributeList<'a> = List<'a, Attribute<'a>>;
/// A list of credentials. Does not reproduce C's incorrect list-size overcount.
pub type CredentialList<'a> = List<'a, Credential<'a>>;
/// A list of credential presentations.
pub type PresentationList<'a> = List<'a, Presentation<'a>>;

/// Iterator over a list already validated in immutable storage.
pub struct Iter<'a, T> {
    rest: &'a [u8],
    left: usize,
    marker: PhantomData<T>,
}
impl<'a, T: Serialized<'a>> Iterator for Iter<'a, T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        if self.left == 0 {
            return None;
        }
        // Only sealed immutable, positive-size decoders construct List. Rechecking
        // here keeps the public iterator memory-safe without unchecked casts.
        let (value, used) = T::decode_prefix(self.rest).ok()?;
        self.rest = self.rest.get(used..)?;
        self.left -= 1;
        Some(value)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}
impl<'a, T: Serialized<'a>> ExactSizeIterator for Iter<'a, T> {}
impl<'a, T: Serialized<'a>> core::iter::FusedIterator for Iter<'a, T> {}

/// Preflight a list of borrowed objects without changing caller storage.
pub fn encoded_len<'a, T: Serialized<'a>>(
    values: &[T],
    limits: ListLimits,
) -> Result<usize, Error> {
    if values.len() > limits.items {
        return Err(Error::Capacity);
    }
    let mut n = 0usize;
    for value in values {
        n = n.checked_add(value.encoded_len()?).ok_or(Error::Overflow)?;
    }
    if n > limits.bytes {
        return Err(Error::Capacity);
    }
    Ok(n)
}
/// Serialize complete objects in input order. No linked-list implementation
/// details or unused capacity are emitted, and failure changes no output bytes.
pub fn encode<'a, T: Serialized<'a>>(
    values: &[T],
    limits: ListLimits,
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = encoded_len(values, limits)?;
    let out = out.get_mut(..n).ok_or(Error::Capacity)?;
    let mut at = 0;
    for value in values {
        let used = value.encode(&mut out[at..])?;
        at += used;
    }
    Ok(n)
}
