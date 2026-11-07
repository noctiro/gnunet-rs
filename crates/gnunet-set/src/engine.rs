//! Shared original-output bookkeeping, not a shared/private peer protocol.
use crate::{
    Limits, Status,
    allocation::Growth,
    content::Body,
    wire::{Abi, PeerMessage},
};
use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use gnunet_types::Error;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Initiator,
    Acceptor,
}
pub(crate) struct ResultValue {
    pub status: Status,
    pub body: Option<Rc<Body>>,
    pub size: u64,
}
pub(crate) struct Output {
    pub frames: VecDeque<Vec<u8>>,
    pub results: VecDeque<ResultValue>,
    pub peer_pending: usize,
    pub bytes: usize,
    limits: Limits,
}
impl Output {
    pub fn new(limits: Limits) -> Self {
        Self {
            frames: VecDeque::new(),
            results: VecDeque::new(),
            peer_pending: 0,
            bytes: 0,
            limits,
        }
    }
    pub fn room(&self) -> bool {
        self.frames.is_empty()
            && self.limits.output_frames != 0
            && self.results.len() < self.limits.output_frames
    }
    pub fn peer(&mut self, message: PeerMessage<'_>, abi: Abi) -> Result<(), Error> {
        self.peer_bounded(message, abi, &mut Growth::new(usize::MAX))
    }
    pub fn peer_bounded(
        &mut self,
        message: PeerMessage<'_>,
        abi: Abi,
        growth: &mut Growth,
    ) -> Result<(), Error> {
        let len = message.encoded_len(abi)?;
        if len > self.limits.output_bytes || self.limits.output_frames == 0 {
            return Err(Error::Capacity);
        }
        if self.frames.len() == self.limits.output_frames
            || self
                .bytes
                .checked_add(len)
                .is_none_or(|n| n > self.limits.output_bytes)
        {
            return Err(Error::WouldBlock);
        }
        growth.grow_deque(&mut self.frames, 1)?;
        let mut bytes = growth.vector(len)?;
        if bytes.capacity() > self.limits.output_bytes {
            return Err(Error::Capacity);
        }
        let charged = self
            .bytes
            .checked_add(bytes.capacity())
            .ok_or(Error::Overflow)?;
        if charged > self.limits.output_bytes {
            return Err(Error::WouldBlock);
        }
        bytes.resize(len, 0);
        message.encode(&mut bytes, abi)?;
        self.frames.push_back(bytes);
        self.bytes = charged;
        Ok(())
    }
    pub fn result(
        &mut self,
        status: Status,
        body: Option<Rc<Body>>,
        size: u64,
    ) -> Result<(), Error> {
        self.result_bounded(status, body, size, &mut Growth::new(usize::MAX))
    }
    pub fn result_bounded(
        &mut self,
        status: Status,
        body: Option<Rc<Body>>,
        size: u64,
        growth: &mut Growth,
    ) -> Result<(), Error> {
        if self.results.len() == self.limits.output_frames {
            return Err(Error::WouldBlock);
        }
        growth.grow_deque(&mut self.results, 1)?;
        self.results.push_back(ResultValue { status, body, size });
        Ok(())
    }
    pub fn transfer(&mut self) -> Result<Vec<u8>, Error> {
        let count = self.peer_pending.checked_add(1).ok_or(Error::Overflow)?;
        let frame = self.frames.pop_front().ok_or(Error::NotReady)?;
        self.bytes = self
            .bytes
            .checked_sub(frame.capacity())
            .ok_or(Error::Stale)?;
        self.peer_pending = count;
        Ok(frame)
    }
    pub fn settled(&mut self) -> Result<(), Error> {
        self.peer_pending = self.peer_pending.checked_sub(1).ok_or(Error::Stale)?;
        Ok(())
    }
    pub fn drained(&self) -> bool {
        self.frames.is_empty() && self.peer_pending == 0
    }
    pub fn clear_unadmitted(&mut self) {
        self.frames.clear();
        self.results.clear();
        self.bytes = 0;
    }
    pub fn charged(&self) -> Result<usize, Error> {
        self.bytes
            .checked_add(
                self.frames
                    .capacity()
                    .checked_mul(core::mem::size_of::<Vec<u8>>())
                    .ok_or(Error::Overflow)?,
            )
            .and_then(|n| {
                self.results
                    .capacity()
                    .checked_mul(core::mem::size_of::<ResultValue>())
                    .and_then(|v| n.checked_add(v))
            })
            .ok_or(Error::Overflow)
    }
}
