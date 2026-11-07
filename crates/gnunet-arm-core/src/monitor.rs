//! Separate monitor MQ with source-exact retry, no artificial timeout/snapshot.
use crate::{
    ConnectionEpoch, FrameSlot, FrameTicket,
    transport::{Frames, Link, Scope},
    wire::{Request, Status},
};
use gnunet_types::{AbsoluteTime, Error};
use gnunet_wire::official::{Frame, message_type as mt};
/// Explicit observation emitted when actual GNUNET_CLIENT MQ creation failed.
/// In C this is service=NULL,statusSTOPPED; it is not a service exit message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable {
    /// Initial creation fails the handle; later failure stops automatic retry only.
    pub initial: bool,
}
/// Caller-owned monitor, borrowing bounded queued-frame storage.
pub struct Monitor<'a> {
    link: Link,
    frames: Frames<'a>,
}
impl<'a> Monitor<'a> {
    /// Create only pure state. No MQ/socket/OS clock is consulted. Epoch must be
    /// nonzero and never reused for reset of the same supplied backing.
    pub fn new(slots: &'a mut [FrameSlot], bytes: &'a mut [u8], epoch: u64) -> Result<Self, Error> {
        if epoch == 0 {
            return Err(Error::InvalidInput);
        }
        let scope = Scope {
            epoch,
            origin: slots.as_ptr() as usize,
        };
        Ok(Self {
            link: Link::new(scope),
            frames: Frames::new(scope, slots, bytes)?,
        })
    }
    /// Lease the next logical MQ creation attempt when due; OS socket retries are
    /// a separate GNUNET_CLIENT transport concern.
    pub fn take_connect(&mut self, now: AbsoluteTime) -> Result<Option<ConnectionEpoch>, Error> {
        self.link.take_connect(now)
    }
    /// Report a genuinely created MQ, then queue the exact MONITOR frame.
    pub fn connection_admitted(&mut self, e: ConnectionEpoch) -> Result<(), Error> {
        self.link.can_report(e)?;
        self.frames.can_push(4)?;
        self.frames.push(Request::Monitor)?;
        self.link.admitted(e)
    }
    /// Report genuine MQ creation failure; no fabricated notification name or timer.
    pub fn connection_unavailable(&mut self, e: ConnectionEpoch) -> Result<Unavailable, Error> {
        Ok(Unavailable {
            initial: self.link.unavailable(e)?,
        })
    }
    /// Report actual retired/lost MQ; old socket/MQ must already be closed by host.
    pub fn connection_lost(&mut self, e: ConnectionEpoch, now: AbsoluteTime) -> Result<(), Error> {
        self.link.lost(e, now)?;
        self.frames.clear();
        Ok(())
    }
    /// Receive one complete frame for this original MQ. Legal unregistered types
    /// are ignored. Registered malformed STATUS retires the MQ and schedules retry.
    pub fn receive<'b>(
        &mut self,
        e: ConnectionEpoch,
        bytes: &'b [u8],
        now: AbsoluteTime,
    ) -> Result<Option<Status<'b>>, Error> {
        self.link.check(e)?;
        let parsed = Frame::decode(bytes).and_then(|f| {
            if f.header().message_type() == mt::ARM_STATUS {
                Status::decode(bytes).map(Some)
            } else {
                Ok(None)
            }
        });
        if parsed.is_err() {
            self.connection_lost(e, now)?;
        }
        parsed
    }
    /// Lease the oldest exact queued frame, persistent across canceled drive calls.
    pub fn take_frame(&mut self) -> Result<Option<FrameTicket>, Error> {
        let e = self.link.current.ok_or(Error::NotReady)?;
        Ok(self.frames.take(e))
    }
    /// Borrow immutable bytes only until the next mutable owner operation.
    pub fn frame(&self, t: FrameTicket) -> Result<&[u8], Error> {
        self.frames
            .view(t, self.link.current.ok_or(Error::StaleGeneration)?)
    }
    /// Report full local frame write, never remote service handling success.
    pub fn frame_written(&mut self, t: FrameTicket) -> Result<(), Error> {
        self.frames
            .written(t, self.link.current.ok_or(Error::StaleGeneration)?)
    }
    /// Recover current frame lease after a canceled host future.
    pub fn current_frame(&self) -> Option<FrameTicket> {
        self.frames.current()
    }
    /// Next source-exact reconnect deadline; no unused5s INIT_TIMEOUT is invented.
    pub const fn next_wakeup(&self) -> Option<AbsoluteTime> {
        self.link.retry
    }
    /// Current escalating retry delay; successful notifications do not reset it.
    pub const fn retry_backoff(&self) -> u64 {
        self.link.backoff
    }
    /// Stop all logical work and invalidate old callbacks. The returned original MQ
    /// is a host close obligation, not a claim that a socket was closed by core.
    #[must_use]
    pub fn stop(&mut self) -> Option<ConnectionEpoch> {
        self.frames.clear();
        self.link.stop()
    }
    /// Whether the monitor can no longer create MQs or deliver notifications.
    pub const fn is_closed(&self) -> bool {
        self.link.closed
    }
}
