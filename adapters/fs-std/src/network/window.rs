//! Network read-ahead for already authenticated sibling references.
use super::{Error, Lookup};
use gnunet_fs::content::{NodeRef, TAG_BYTES};
use gnunet_service_runtime::framing::ReadStep;
use gnunet_types::Error as Fault;
use gnunet_wire::official::fs::{BlockType, Response};
use std::{
    future::poll_fn,
    io,
    task::{Context, Poll},
};

// A single native MQ retains about 2 MiB of reordered ciphertext even when
// the operator admits a larger number of outstanding requests globally.
const MAX_BUFFERED: usize = 64;

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Unsent,
    Queued,
    Written,
    Ready,
}

struct Slot {
    request: NodeRef,
    leader: usize,
    state: State,
    block: Vec<u8>,
}

#[derive(Default)]
pub(super) struct Window {
    slots: Vec<Slot>,
    count: usize,
    front: usize,
}

impl Window {
    pub(super) fn has_pending(&self) -> bool {
        self.front < self.count
    }
    /// A partial active window can only continue with its exact next reference.
    /// A singleton falls through to the original zero-copy MQ path.
    pub(super) fn select(
        &mut self,
        lookup: &mut Lookup,
        request: NodeRef,
        leaves: impl Iterator<Item = NodeRef>,
    ) -> Result<bool, Error> {
        if self.front < self.count {
            if self.slots[self.front].request != request {
                return Err(Fault::Stale.into());
            }
            return Ok(true);
        }
        let rotate = lookup.queries == lookup.options.queries_per_connection;
        let remaining = if rotate || !lookup.connected {
            lookup.options.queries_per_connection
        } else {
            lookup.options.queries_per_connection - lookup.queries
        };
        let capacity = lookup
            .options
            .request_parallelism
            .get()
            .min(remaining)
            .min(MAX_BUFFERED as u32) as usize;
        if capacity < 2 {
            return Ok(false);
        }
        let mut leaves = leaves.take(capacity);
        let (Some(first), Some(second)) = (leaves.next(), leaves.next()) else {
            return Ok(false);
        };
        if first != request {
            return Err(Fault::Stale.into());
        }
        self.count = 0;
        self.front = 0;
        for request in [first, second].into_iter().chain(leaves) {
            self.add(request)?;
        }
        if rotate {
            lookup.channel.detach();
            lookup.connected = false;
            lookup.queries = 0;
        }
        Ok(true)
    }

    fn add(&mut self, request: NodeRef) -> Result<(), Error> {
        let leader = self.slots[..self.count]
            .iter()
            .position(|slot| slot.request.key().query == request.key().query)
            .unwrap_or(self.count);
        if self.count == self.slots.len() {
            self.slots.try_reserve(1).map_err(|_| Fault::Capacity)?;
            self.slots.push(Slot {
                request,
                leader,
                state: State::Unsent,
                block: Vec::new(),
            });
        } else {
            let slot = &mut self.slots[self.count];
            slot.request = request;
            slot.leader = leader;
            slot.state = State::Unsent;
            slot.block.clear();
        }
        self.count += 1;
        Ok(())
    }

    pub(super) async fn fetch(&mut self, lookup: &mut Lookup) -> Result<(), Error> {
        poll_fn(|cx| self.poll_front(lookup, cx)).await
    }

    fn poll_front(&mut self, lookup: &mut Lookup, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match lookup.time(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        if self.ready() {
            return Poll::Ready(Ok(()));
        }
        match lookup.attach(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        let framed = lookup.channel.framing().ok_or(Fault::NotReady)?;
        if framed.queued_frames() == 0
            && let Some((index, slot)) = self.slots[..self.count]
                .iter_mut()
                .enumerate()
                .find(|(index, slot)| *index == slot.leader && slot.state == State::Unsent)
        {
            if lookup.queries >= lookup.options.queries_per_connection {
                return Poll::Ready(Err(Fault::Capacity.into()));
            }
            lookup.queue(index as u64, BlockType::DBLOCK, slot.request.key().query)?;
            slot.state = State::Queued;
        }
        let framed = lookup.channel.framing_mut().ok_or(Fault::NotReady)?;
        let mut progress = false;
        if framed.queued_frames() != 0 {
            match framed.poll_write(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => return self.reconnect(lookup, error, cx),
                Poll::Ready(Ok(step)) => {
                    let index = step.origin as usize;
                    let slot = self.slots.get_mut(index).ok_or(Fault::Stale)?;
                    if index >= self.count || slot.leader != index || slot.state != State::Queued {
                        return Poll::Ready(Err(Fault::Stale.into()));
                    }
                    if step.complete {
                        slot.state = State::Written;
                    }
                    progress = true;
                }
            }
        }
        if let Some(frame) = framed.frame() {
            self.accept(Response::decode(frame)?)?;
            framed.release_frame();
            if self.ready() {
                return Poll::Ready(Ok(()));
            }
            progress = true;
        } else {
            match framed.poll_read(cx) {
                Poll::Pending => {}
                Poll::Ready(Ok(ReadStep::Progress { .. })) => progress = true,
                Poll::Ready(Ok(ReadStep::Eof)) => {
                    return self.reconnect(
                        lookup,
                        io::Error::new(io::ErrorKind::UnexpectedEof, "FS lookup MQ closed"),
                        cx,
                    );
                }
                Poll::Ready(Err(error)) => return self.reconnect(lookup, error, cx),
            }
        }
        if progress {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn accept(&mut self, response: Response<'_>) -> Result<(), Error> {
        let put = match response {
            Response::Put(put) => put,
            Response::Unknown(_) => return Ok(()),
            _ => return Err(Fault::Malformed.into()),
        };
        let query = gnunet_crypto::hash512(put.block);
        if let Some(slot) = self.slots[..self.count]
            .iter_mut()
            .find(|slot| slot.state == State::Written && slot.request.key().query == query)
        {
            if put.block_type != BlockType::DBLOCK
                || put.block.len() != slot.request.node().plaintext_bytes() + TAG_BYTES
            {
                return Err(Fault::Authentication.into());
            }
            slot.block
                .try_reserve_exact(put.block.len())
                .map_err(|_| Fault::Capacity)?;
            slot.block.extend_from_slice(put.block);
            slot.state = State::Ready;
        }
        Ok(())
    }

    fn reconnect(
        &mut self,
        lookup: &mut Lookup,
        error: io::Error,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        lookup.lost(error)?;
        for slot in &mut self.slots[..self.count] {
            if slot.state != State::Ready {
                slot.state = State::Unsent;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn ready(&self) -> bool {
        self.front < self.count && self.slots[self.slots[self.front].leader].state == State::Ready
    }

    pub(super) fn block(&self) -> Result<&[u8], Error> {
        if !self.ready() {
            return Err(Fault::NotReady.into());
        }
        Ok(&self.slots[self.slots[self.front].leader].block)
    }

    pub(super) fn release(&mut self) {
        self.front += 1;
    }
}
