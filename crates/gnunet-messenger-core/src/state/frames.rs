//! Exclusive original byte storage and the separate history workspace.

use crate::{
    BorrowedBytes, ByteSlot, Error, OriginalPool, archive::ArchiveOriginalRange,
    custody::LocalOriginal,
};
use core::ops::{Deref, DerefMut};
use gnunet_types::Error as Fault;
use zeroize::Zeroize;
#[cfg(feature = "alloc")]
use {crate::OwnedBytes, alloc::vec::Vec, zeroize::Zeroizing};

#[cfg_attr(feature = "alloc", derive(Default))]
pub(crate) enum ByteStore<'id> {
    #[cfg(feature = "alloc")]
    #[default]
    Heap,
    Fixed(OriginalPool<'id, 'id>),
}

#[cfg_attr(feature = "alloc", derive(Default))]
pub(crate) struct FrameStore<'id> {
    bytes: ByteStore<'id>,
    workspace: Option<FrameWorkspace<'id>>,
}

pub(crate) enum RetainedFrame {
    #[cfg(feature = "alloc")]
    Heap(OwnedBytes),
    Fixed {
        id: LocalOriginal,
        len: usize,
    },
    Archived(ArchiveOriginalRange),
}

#[cfg(feature = "alloc")]
impl From<OwnedBytes> for RetainedFrame {
    fn from(bytes: OwnedBytes) -> Self {
        Self::Heap(bytes)
    }
}

impl RetainedFrame {
    /// Resident bytes charged to Core; committed archive ranges own no bytes.
    pub fn capacity(&self) -> usize {
        match self {
            #[cfg(feature = "alloc")]
            Self::Heap(bytes) => bytes.capacity(),
            Self::Fixed { len, .. } => *len,
            Self::Archived(_) => 0,
        }
    }

    pub const fn archived_original(&self) -> Option<ArchiveOriginalRange> {
        match self {
            Self::Archived(range) => Some(*range),
            _ => None,
        }
    }

    pub const fn is_resident(&self) -> bool {
        !matches!(self, Self::Archived(_))
    }
}

pub(crate) trait IncomingFrame: Sized {
    fn bytes(&self) -> &[u8];
    #[cfg(feature = "alloc")]
    fn heap_charge(&self) -> usize;
    #[cfg(feature = "alloc")]
    fn adopt(self, budget: usize) -> Result<OwnedBytes, (Error, Self)>;
}

#[cfg(feature = "alloc")]
impl IncomingFrame for OwnedBytes {
    fn bytes(&self) -> &[u8] {
        self.expose()
    }

    #[cfg(feature = "alloc")]
    fn heap_charge(&self) -> usize {
        self.capacity()
    }

    #[cfg(feature = "alloc")]
    fn adopt(self, _budget: usize) -> Result<OwnedBytes, (Error, Self)> {
        Ok(self)
    }
}

impl IncomingFrame for &[u8] {
    fn bytes(&self) -> &[u8] {
        self
    }

    #[cfg(feature = "alloc")]
    fn heap_charge(&self) -> usize {
        self.len()
    }

    #[cfg(feature = "alloc")]
    fn adopt(self, budget: usize) -> Result<OwnedBytes, (Error, Self)> {
        let retained = OwnedBytes::copy_from(self).map_err(|error| (error, self))?;
        if retained.capacity() > budget {
            return Err((Fault::Capacity.into(), self));
        }
        Ok(retained)
    }
}

impl ByteStore<'_> {
    #[cfg(feature = "alloc")]
    pub fn take_owned(&mut self, frame: &mut Option<RetainedFrame>) -> Result<OwnedBytes, Error> {
        match frame.take() {
            Some(RetainedFrame::Heap(bytes)) => Ok(bytes),
            Some(archived @ RetainedFrame::Archived(_)) => {
                *frame = Some(archived);
                Err(Fault::NotReady.into())
            }
            Some(fixed) => {
                *frame = Some(fixed);
                Err(Fault::Capacity.into())
            }
            None => Err(Fault::Conflict.into()),
        }
    }

    pub fn take_into<'slot, 'buffer>(
        &mut self,
        frame: &mut Option<RetainedFrame>,
        slot: &'slot ByteSlot<'buffer>,
    ) -> Result<BorrowedBytes<'slot, 'buffer>, Error> {
        let taken = match frame.as_ref().ok_or(Fault::Conflict)? {
            #[cfg(feature = "alloc")]
            RetainedFrame::Heap(bytes) => slot.copy_from(bytes.expose())?,
            fixed @ RetainedFrame::Fixed { .. } => {
                self.consume_fixed(fixed, |bytes| slot.copy_from(bytes))?
            }
            RetainedFrame::Archived(_) => return Err(Fault::NotReady.into()),
        };
        *frame = None;
        Ok(taken)
    }

    pub fn consume_fixed<T>(
        &mut self,
        frame: &RetainedFrame,
        accept: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        match (self, frame) {
            (Self::Fixed(pool), RetainedFrame::Fixed { id, .. }) => {
                pool.consume(pool.bind_local(*id)?, accept)
            }
            (_, RetainedFrame::Archived(_)) => Err(Fault::NotReady.into()),
            #[cfg(feature = "alloc")]
            _ => Err(Fault::StaleGeneration.into()),
        }
    }

    pub fn charge_for(&self, input: &impl IncomingFrame) -> usize {
        match self {
            #[cfg(feature = "alloc")]
            Self::Heap => input.heap_charge(),
            Self::Fixed(_) => input.bytes().len(),
        }
    }

    pub fn retain<I: IncomingFrame>(
        &mut self,
        input: I,
        replacing: Option<&RetainedFrame>,
        budget: usize,
    ) -> Result<RetainedFrame, (Error, I)> {
        if self.charge_for(&input) > budget {
            return Err((Fault::Capacity.into(), input));
        }
        match self {
            #[cfg(feature = "alloc")]
            Self::Heap => {
                if replacing.is_some_and(|frame| !matches!(frame, RetainedFrame::Heap(_))) {
                    return Err((Fault::StaleGeneration.into(), input));
                }
                // An already-owned input keeps its exact allocation; on success
                // the previous row's heap bytes drop with that row.
                input.adopt(budget).map(RetainedFrame::Heap)
            }
            Self::Fixed(pool) => {
                let bytes = input.bytes();
                let len = bytes.len();
                let result = match replacing {
                    None => pool.copy_from(bytes),
                    Some(RetainedFrame::Fixed { id, .. }) => pool
                        .bind_local(*id)
                        .and_then(|id| pool.replace_from_slice(id, bytes)),
                    Some(_) => Err(Fault::StaleGeneration.into()),
                };
                match result {
                    Ok(id) => Ok(RetainedFrame::Fixed {
                        id: id.local(),
                        len,
                    }),
                    Err(error) => Err((error, input)),
                }
            }
        }
    }

    pub fn write(
        &mut self,
        len: usize,
        budget: usize,
        write: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<RetainedFrame, Error> {
        if len > budget {
            return Err(Fault::Capacity.into());
        }
        match self {
            #[cfg(feature = "alloc")]
            Self::Heap => {
                let mut bytes = Zeroizing::new(Vec::new());
                bytes.try_reserve_exact(len).map_err(|_| Fault::Capacity)?;
                if bytes.capacity() > budget {
                    return Err(Fault::Capacity.into());
                }
                bytes.resize(len, 0);
                write(&mut bytes)?;
                Ok(RetainedFrame::Heap(OwnedBytes::new(bytes)))
            }
            Self::Fixed(pool) => {
                let id = pool.write(len, write)?.local();
                Ok(RetainedFrame::Fixed { id, len })
            }
        }
    }

    pub fn expose<'a>(&'a self, frame: &'a RetainedFrame) -> Result<&'a [u8], Error> {
        match (self, frame) {
            #[cfg(feature = "alloc")]
            (Self::Heap, RetainedFrame::Heap(bytes)) => Ok(bytes.expose()),
            (Self::Fixed(pool), RetainedFrame::Fixed { id, .. }) => {
                pool.expose(pool.bind_local(*id)?)
            }
            (_, RetainedFrame::Archived(_)) => Err(Fault::NotReady.into()),
            #[cfg(feature = "alloc")]
            _ => Err(Fault::StaleGeneration.into()),
        }
    }

    pub fn remove(&mut self, frame: RetainedFrame) -> Result<(), Error> {
        match (self, frame) {
            #[cfg(feature = "alloc")]
            (Self::Heap, RetainedFrame::Heap(_)) => Ok(()),
            (Self::Fixed(pool), RetainedFrame::Fixed { id, .. }) => {
                pool.remove(pool.bind_local(id)?)
            }
            // The archive is owned and replaced by the persistence boundary.
            // Erasing a history vertex drops only its reference to those bytes.
            (_, RetainedFrame::Archived(_)) => Ok(()),
            #[cfg(feature = "alloc")]
            _ => Err(Fault::StaleGeneration.into()),
        }
    }
}

impl<'id> Deref for FrameStore<'id> {
    type Target = ByteStore<'id>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for FrameStore<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl<'id> FrameStore<'id> {
    pub fn fixed(pool: OriginalPool<'id, 'id>, buffer: &'id mut [u8]) -> Self {
        buffer.zeroize();
        Self {
            bytes: ByteStore::Fixed(pool),
            workspace: Some(FrameWorkspace { buffer, used: 0 }),
        }
    }

    pub fn copy(&mut self, bytes: &[u8], budget: usize) -> Result<RetainedFrame, Error> {
        self.retain(bytes, None, budget).map_err(|(error, _)| error)
    }

    pub fn checkout(
        &mut self,
        frame: RetainedFrame,
    ) -> Result<WorkingFrame<'id>, (Error, RetainedFrame)> {
        match (&self.bytes, frame) {
            #[cfg(feature = "alloc")]
            (ByteStore::Heap, RetainedFrame::Heap(bytes)) => Ok(WorkingFrame::Heap(bytes)),
            (ByteStore::Fixed(pool), frame @ RetainedFrame::Fixed { id, .. }) => {
                let bytes = match pool.bind_local(id).and_then(|id| pool.expose(id)) {
                    Ok(bytes) => bytes,
                    Err(error) => return Err((error, frame)),
                };
                let Some(mut scratch) = self.workspace.take() else {
                    return Err((Fault::Conflict.into(), frame));
                };
                let Some(out) = scratch.buffer.get_mut(..bytes.len()) else {
                    self.workspace = Some(scratch);
                    return Err((Fault::Capacity.into(), frame));
                };
                out.copy_from_slice(bytes);
                scratch.used = bytes.len();
                Ok(WorkingFrame::Fixed {
                    retained: frame,
                    scratch,
                })
            }
            (_, archived @ RetainedFrame::Archived(_)) => Err((Fault::NotReady.into(), archived)),
            #[cfg(feature = "alloc")]
            (_, frame) => Err((Fault::StaleGeneration.into(), frame)),
        }
    }

    pub fn checkin(&mut self, working: WorkingFrame<'id>) -> Result<RetainedFrame, Error> {
        match (&self.bytes, working) {
            #[cfg(feature = "alloc")]
            (ByteStore::Heap, WorkingFrame::Heap(bytes)) => Ok(RetainedFrame::Heap(bytes)),
            (
                ByteStore::Fixed(_),
                WorkingFrame::Fixed {
                    retained,
                    mut scratch,
                },
            ) if self.workspace.is_none() => {
                scratch.clear();
                self.workspace = Some(scratch);
                Ok(retained)
            }
            _ => Err(Fault::Conflict.into()),
        }
    }
}

pub(crate) struct FrameWorkspace<'id> {
    buffer: &'id mut [u8],
    used: usize,
}

impl FrameWorkspace<'_> {
    fn clear(&mut self) {
        self.buffer[..self.used].zeroize();
        self.used = 0;
    }
}

impl Drop for FrameWorkspace<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Desktop lends its existing allocation. Fixed storage lends one separate
/// erased slot so the room can mutate/compact the pool during interpretation.
pub(crate) enum WorkingFrame<'id> {
    #[cfg(feature = "alloc")]
    Heap(OwnedBytes),
    Fixed {
        retained: RetainedFrame,
        scratch: FrameWorkspace<'id>,
    },
}

impl WorkingFrame<'_> {
    pub fn bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "alloc")]
            Self::Heap(bytes) => bytes.expose(),
            Self::Fixed { scratch, .. } => &scratch.buffer[..scratch.used],
        }
    }
}
