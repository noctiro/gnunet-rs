//! Bounded storage for the shared phase machine.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use gnunet_types::Error;
use zeroize::Zeroize;
#[cfg(feature = "alloc")]
use zeroize::Zeroizing;

pub(super) enum Directory<T, const N: usize> {
    Fixed([Option<T>; N]),
    #[cfg(feature = "alloc")]
    Shared(Vec<Option<T>>),
}

impl<T, const N: usize> Directory<T, N> {
    pub(super) const fn inline() -> Self {
        Self::Fixed([const { None }; N])
    }

    #[cfg(feature = "alloc")]
    pub(super) fn shared(len: usize) -> Result<Self, Error> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
        rows.resize_with(len, || None);
        Ok(Self::Shared(rows))
    }
}

impl<T, const N: usize> Deref for Directory<T, N> {
    type Target = [Option<T>];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Fixed(rows) => rows,
            #[cfg(feature = "alloc")]
            Self::Shared(rows) => rows,
        }
    }
}

impl<T, const N: usize> DerefMut for Directory<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Fixed(rows) => rows,
            #[cfg(feature = "alloc")]
            Self::Shared(rows) => rows,
        }
    }
}

pub(super) enum Payload {
    Fixed(usize),
    #[cfg(feature = "alloc")]
    Shared(Zeroizing<Vec<u8>>),
}

impl Payload {
    pub(super) fn charge(&self) -> usize {
        match self {
            Self::Fixed(len) => *len,
            #[cfg(feature = "alloc")]
            Self::Shared(bytes) => bytes.capacity(),
        }
    }
}

pub(super) enum Payloads<'space> {
    Fixed {
        bytes: &'space mut [u8],
        lane: usize,
    },
    #[cfg(feature = "alloc")]
    Shared,
}

impl Payloads<'_> {
    pub(super) fn get<'a>(&'a self, row: usize, payload: &'a Payload) -> Result<&'a [u8], Error> {
        match (self, payload) {
            (Self::Fixed { bytes, lane }, Payload::Fixed(len)) => {
                cell(bytes, *lane, row)?.get(..*len).ok_or(Error::Conflict)
            }
            #[cfg(feature = "alloc")]
            (Self::Shared, Payload::Shared(bytes)) => Ok(bytes),
            #[cfg(feature = "alloc")]
            _ => Err(Error::Conflict),
        }
    }

    pub(super) fn insert(
        &mut self,
        row: usize,
        free: usize,
        bytes: &[u8],
    ) -> Result<Payload, Error> {
        if bytes.len() > free {
            return Err(Error::Capacity);
        }
        match self {
            Self::Fixed { bytes: arena, lane } => {
                let cell = cell_mut(arena, *lane, row)?;
                cell.get_mut(..bytes.len())
                    .ok_or(Error::Capacity)?
                    .copy_from_slice(bytes);
                Ok(Payload::Fixed(bytes.len()))
            }
            #[cfg(feature = "alloc")]
            Self::Shared => shared(bytes, free),
        }
    }

    pub(super) fn replace(
        &mut self,
        row: usize,
        current: &mut Payload,
        free: usize,
        bytes: &[u8],
    ) -> Result<(), Error> {
        match (self, current) {
            (Self::Fixed { bytes: arena, lane }, Payload::Fixed(len)) => {
                if bytes.len().saturating_sub(*len) > free {
                    return Err(Error::Capacity);
                }
                let cell = cell_mut(arena, *lane, row)?;
                let output = cell
                    .get_mut(..bytes.len().max(*len))
                    .ok_or(Error::Capacity)?;
                let (body, tail) = output.split_at_mut(bytes.len());
                body.copy_from_slice(bytes);
                tail.zeroize();
                *len = bytes.len();
            }
            #[cfg(feature = "alloc")]
            (Self::Shared, Payload::Shared(buffer)) if bytes.len() <= buffer.capacity() => {
                buffer[..].zeroize();
                buffer.resize(bytes.len(), 0);
                buffer.copy_from_slice(bytes);
            }
            #[cfg(feature = "alloc")]
            (Self::Shared, current @ Payload::Shared(_)) => *current = shared(bytes, free)?,
            #[cfg(feature = "alloc")]
            _ => return Err(Error::Conflict),
        }
        Ok(())
    }

    pub(super) fn release(&mut self, row: usize, payload: &Payload) -> Result<(), Error> {
        match (self, payload) {
            (Self::Fixed { bytes, lane }, Payload::Fixed(len)) => {
                cell_mut(bytes, *lane, row)?
                    .get_mut(..*len)
                    .ok_or(Error::Conflict)?
                    .zeroize();
            }
            #[cfg(feature = "alloc")]
            (Self::Shared, Payload::Shared(_)) => {}
            #[cfg(feature = "alloc")]
            _ => return Err(Error::Conflict),
        }
        Ok(())
    }
}

impl Drop for Payloads<'_> {
    fn drop(&mut self) {
        match self {
            Self::Fixed { bytes, .. } => bytes.zeroize(),
            #[cfg(feature = "alloc")]
            Self::Shared => {}
        }
    }
}

fn cell(bytes: &[u8], lane: usize, row: usize) -> Result<&[u8], Error> {
    bytes.chunks_exact(lane).nth(row).ok_or(Error::Conflict)
}

fn cell_mut(bytes: &mut [u8], lane: usize, row: usize) -> Result<&mut [u8], Error> {
    bytes.chunks_exact_mut(lane).nth(row).ok_or(Error::Conflict)
}

#[cfg(feature = "alloc")]
fn shared(bytes: &[u8], free: usize) -> Result<Payload, Error> {
    if bytes.len() > free {
        return Err(Error::Capacity);
    }
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(bytes.len())
        .map_err(|_| Error::Capacity)?;
    if buffer.capacity() > free {
        return Err(Error::Capacity);
    }
    buffer.extend_from_slice(bytes);
    Ok(Payload::Shared(Zeroizing::new(buffer)))
}
