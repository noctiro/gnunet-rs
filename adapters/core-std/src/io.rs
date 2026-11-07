//! Domain budgets over the shared original physical framing owner.
use gnunet_service_runtime::{
    connection::Connection,
    framing::{Accounting, Budget, Class, Framed, Limits, OwnedFrame, ReadStep},
};
use gnunet_types::Error;
use std::{
    io,
    task::{Context, Poll},
};
pub(crate) struct Link {
    io: Framed<()>,
}
impl Link {
    pub(crate) fn new(
        connection: Connection,
        limit: usize,
        frames: usize,
        slice: usize,
    ) -> Result<Self, Error> {
        if limit < 65535 || frames == 0 || slice == 0 {
            return Err(Error::Capacity);
        }
        Ok(Self {
            io: Framed::new(
                connection,
                Limits {
                    frame_bytes: 65535,
                    ordinary: Budget {
                        frames,
                        bytes: limit,
                    },
                    reserved: Budget::default(),
                    accounting: Accounting::Retained,
                    io_slice_bytes: slice,
                },
            )?,
        })
    }
    pub(crate) fn capacity(&self, bytes: usize) -> bool {
        self.io.capacity(bytes, Class::Ordinary)
    }
    pub(crate) fn control_reserve(&mut self, frames: usize) -> Result<(), Error> {
        self.io.set_reserved(Budget {
            frames,
            bytes: frames.checked_mul(40).ok_or(Error::Capacity)?,
        })
    }
    pub(crate) fn control_capacity(&self, bytes: usize) -> bool {
        bytes <= 40 && self.io.capacity(bytes, Class::Reserved)
    }
    pub(crate) fn reserve(&mut self, bytes: usize, control: bool) -> Result<(), Error> {
        if control && bytes > 40 {
            return Err(Error::WouldBlock);
        }
        self.io.reserve(
            bytes,
            if control {
                Class::Reserved
            } else {
                Class::Ordinary
            },
        )
    }
    pub(crate) fn cancel_unwritten(&mut self, mut matches: impl FnMut(&[u8]) -> bool) -> usize {
        self.io
            .remove_unwritten(|(), bytes| matches(bytes), |(), _| {})
    }
    pub(crate) fn enqueue(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        self.enqueue_inner(bytes, false)
    }
    pub(crate) fn enqueue_control(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        self.enqueue_inner(bytes, true)
    }
    fn enqueue_inner(&mut self, bytes: Vec<u8>, control: bool) -> Result<(), Error> {
        let bytes = OwnedFrame::new(bytes);
        if control && bytes.len() > 40 {
            return Err(Error::WouldBlock);
        }
        self.io
            .enqueue_owned(
                bytes,
                (),
                if control {
                    Class::Reserved
                } else {
                    Class::Ordinary
                },
            )
            .map_err(|rejected| rejected.reason)
    }
    pub(crate) fn frame(&self) -> Option<&[u8]> {
        self.io.frame()
    }
    pub(crate) fn release(&mut self) {
        self.io.release_frame();
    }
    pub(crate) fn poll_rx(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        self.io.poll_read(cx).map(|result| {
            result.and_then(|step| match step {
                ReadStep::Progress { complete, .. } => Ok(complete),
                ReadStep::Eof => Err(io::ErrorKind::UnexpectedEof.into()),
            })
        })
    }
    pub(crate) fn poll_tx(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_write(cx).map(|result| result.map(|_| ()))
    }
}
