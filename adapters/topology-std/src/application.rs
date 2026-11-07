//! Actual official TRANSPORT application1300/1301, one bounded original change.
use crate::{Bound, Error, Event};
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::framing::{
    Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep,
};
use gnunet_topology::Control;
use gnunet_transport::{PeerId, application::Preference};
use gnunet_types::Error as Fault;
use std::task::{Context, Poll};
use tokio::time::Instant;
#[derive(Clone, Copy)]
struct Write {
    epoch: u64,
    sequence: u64,
    last: bool,
}
struct Pending {
    job: Control,
    sequence: u64,
    bound: Bound,
    bytes: usize,
}
#[derive(Debug)]
pub(crate) struct Retired {
    pub epoch: u64,
    pub job: Option<Control>,
    pub bytes: usize,
}
pub(crate) enum Step {
    Activity,
    Written(Control),
    Lost(Retired),
}
pub(crate) struct Application {
    source: EndpointSource,
    channel: Channel<Write>,
    pending: Option<Pending>,
    epoch: u64,
    next: u64,
    attached: bool,
    io: usize,
}
fn framing(io: usize) -> FrameLimits {
    FrameLimits {
        frame_bytes: 65535,
        ordinary: Budget {
            frames: 2,
            bytes: 88,
        },
        reserved: Budget::default(),
        accounting: Accounting::Retained,
        io_slice_bytes: io,
    }
}
impl Application {
    pub fn new(source: EndpointSource, io: usize) -> Result<Self, Error> {
        Ok(Self {
            channel: Channel::new(source.duplicate()?, framing(io))?,
            source,
            pending: None,
            epoch: 0,
            next: 0,
            attached: false,
            io,
        })
    }
    pub fn ready(&self) -> bool {
        self.attached && self.pending.is_none()
    }
    pub fn next_native(&self) -> Option<Instant> {
        self.pending.as_ref().map(|p| p.bound.hard)
    }
    pub fn next_logical(&self) -> Option<u64> {
        self.pending.as_ref().map(|p| p.bound.until)
    }
    pub fn enqueue(&mut self, job: Control, peer: [u8; 32], bound: Bound) -> Result<(), Error> {
        if !self.ready() {
            return Err(Fault::WouldBlock.into());
        }
        let mut frames = Vec::new();
        frames.try_reserve_exact(2).map_err(|_| Fault::Capacity)?;
        let preference = Preference {
            priority: 1,
            peer: PeerId(peer),
            bandwidth: 0,
        };
        for cancel in [true, false] {
            if (cancel && job.before() == 0) || (!cancel && job.after() == 0) {
                continue;
            }
            let mut data = Vec::new();
            data.try_reserve_exact(44).map_err(|_| Fault::Capacity)?;
            data.resize(44, 0);
            preference.encode(cancel, &mut data)?;
            frames.push(OwnedFrame::new(data));
        }
        let total = frames.len();
        if total == 0 {
            return Err(Fault::InvalidInput.into());
        }
        let sequence = self.next.checked_add(1).ok_or(Fault::Overflow)?;
        self.next = sequence;
        for (index, frame) in frames.into_iter().enumerate() {
            if let Err(e) = self
                .channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .enqueue_owned(
                    frame,
                    Write {
                        epoch: self.epoch,
                        sequence,
                        last: index + 1 == total,
                    },
                    Class::Ordinary,
                )
            {
                self.channel.close();
                self.attached = false;
                return Err(e.reason.into());
            }
        }
        self.pending = Some(Pending {
            job,
            sequence,
            bound,
            bytes: 0,
        });
        Ok(())
    }
    pub fn expired(&self, now: Option<u64>) -> bool {
        self.pending.as_ref().is_some_and(|p| {
            Instant::now() >= p.bound.hard || now.is_some_and(|now| now >= p.bound.until)
        })
    }
    pub fn rotate<'id>(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<Retired, Error> {
        self.channel.close();
        self.attached = false;
        let pending = self.pending.take();
        let retired = Retired {
            epoch: self.epoch,
            bytes: pending.as_ref().map_or(0, |p| p.bytes),
            job: pending.map(|p| p.job),
        };
        observe(Event::ApplicationRetired {
            epoch: retired.epoch,
            job: retired.job.clone(),
            bytes: retired.bytes,
        });
        self.channel = Channel::new(self.source.duplicate()?, framing(self.io))?;
        Ok(retired)
    }
    pub fn attached(&self) -> bool {
        self.attached
    }
    pub fn close(&mut self) -> Retired {
        self.channel.close();
        self.attached = false;
        let pending = self.pending.take();
        Retired {
            epoch: self.epoch,
            bytes: pending.as_ref().map_or(0, |p| p.bytes),
            job: pending.map(|p| p.job),
        }
    }
    pub fn poll<'id>(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Step, Error>> {
        match self.channel.poll_clock(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Pending => return Poll::Pending,
        }
        if !self.attached {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    self.epoch = self.epoch.checked_add(1).ok_or(Fault::Overflow)?;
                    self.attached = true;
                    observe(Event::ApplicationAttached(self.epoch));
                    Poll::Ready(Ok(Step::Activity))
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                    observe(Event::Io("transport retry", error));
                    Poll::Ready(Ok(Step::Activity))
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => Poll::Ready(Err(e.into())),
            };
        }
        if self.pending.is_some() {
            match self
                .channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .poll_write(cx)
            {
                Poll::Ready(Ok(w)) => {
                    let pending = self.pending.as_mut().ok_or(Fault::Stale)?;
                    if w.origin.epoch != self.epoch || w.origin.sequence != pending.sequence {
                        return Poll::Ready(Err(Fault::Stale.into()));
                    }
                    pending.bytes = pending.bytes.checked_add(w.bytes).ok_or(Fault::Overflow)?;
                    if w.complete && w.origin.last {
                        let p = self.pending.take().ok_or(Fault::Stale)?;
                        observe(Event::ApplicationWritten(
                            self.epoch,
                            p.job.clone(),
                            p.bytes,
                        ));
                        return Poll::Ready(Ok(Step::Written(p.job)));
                    }
                    return Poll::Ready(Ok(Step::Activity));
                }
                Poll::Ready(Err(e)) => {
                    observe(Event::Io("transport write", e));
                    let old = self.rotate(observe)?;
                    return Poll::Ready(Ok(Step::Lost(old)));
                }
                Poll::Pending => {}
            }
        }
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_read(cx)
        {
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(Ok(Step::Lost(self.rotate(observe)?))),
            Poll::Ready(Err(e)) => {
                observe(Event::Io("transport read", e));
                Poll::Ready(Ok(Step::Lost(self.rotate(observe)?)))
            }
            Poll::Ready(Ok(ReadStep::Progress { complete: true, .. })) => {
                Poll::Ready(Err(Fault::Malformed.into()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(Step::Activity)),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Drop for Application {
    fn drop(&mut self) {
        self.channel.close();
    }
}
