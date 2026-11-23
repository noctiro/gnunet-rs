//! Exact original loans under the filter's native admission mutex.
use super::super::handle::Handle;
use std::{
    io,
    sync::{Arc, Weak},
};

#[derive(Clone, Copy)]
pub(super) enum Direction {
    Receive,
    Send,
}
impl Direction {
    const fn index(self) -> usize {
        match self {
            Self::Receive => 0,
            Self::Send => 1,
        }
    }
}
struct Slot<T> {
    owner: Weak<T>,
    observation: Option<io::Result<u32>>,
}
pub(super) struct Admission<T> {
    handle: Handle,
    slots: [Option<Slot<T>>; 2],
}
impl<T> Admission<T> {
    pub fn new(handle: usize) -> Self {
        Self {
            handle: Handle::Open(handle),
            slots: [None, None],
        }
    }

    pub fn original(&self) -> io::Result<usize> {
        self.handle.original()
    }

    /// Register before lending memory. A refused submission cannot leave an
    /// original in the close-time query set; the native callback is not armed yet.
    pub fn submit(
        &mut self,
        direction: Direction,
        owner: &Arc<T>,
        submit: impl FnOnce(usize) -> io::Result<()>,
    ) -> io::Result<()> {
        let handle = self.original()?;
        let slot = &mut self.slots[direction.index()];
        if slot.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        *slot = Some(Slot {
            owner: Arc::downgrade(owner),
            observation: None,
        });
        let result = submit(handle);
        if result.is_err() {
            *slot = None;
        }
        result
    }

    /// Remove this exact original before any result or directional credit can
    /// be published. Close may never query memory already returned to its caller.
    pub fn complete(
        &mut self,
        direction: Direction,
        owner: &Arc<T>,
        query: impl FnOnce(usize, &T) -> io::Result<u32>,
    ) -> io::Result<io::Result<u32>> {
        let Some(slot) = self.slots[direction.index()]
            .take_if(|slot| std::ptr::eq(slot.owner.as_ptr(), Arc::as_ptr(owner)))
        else {
            return Err(io::Error::other(
                "WinDivert original loan is not registered",
            ));
        };
        if let Some(observation) = slot.observation {
            return Ok(observation);
        }
        self.original().map(|handle| query(handle, owner))
    }

    /// Sample each still-registered original at most once, without waiting.
    /// Only terminal native results are retained; None leaves status unknown.
    /// No extra handle or wait for pending I/O defers the original close.
    pub fn close(
        &mut self,
        mut query: impl FnMut(usize, &T) -> Option<io::Result<u32>>,
        close: impl FnOnce(usize) -> Result<(), i32>,
    ) -> io::Result<()> {
        let Self { handle, slots } = self;
        handle.close(|raw| {
            for slot in slots.iter_mut().flatten() {
                if slot.observation.is_none()
                    && let Some(owner) = slot.owner.upgrade()
                {
                    slot.observation = query(raw, &owner);
                }
            }
            close(raw)
        })
    }
}

#[cfg(test)]
#[path = "admission/tests.rs"]
mod tests;
