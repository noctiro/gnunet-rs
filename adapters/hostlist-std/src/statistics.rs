//! Bounded absolute counter snapshots on the actual STATISTICS MQ. No SET ACK is
//! invented; retired partial frames are reported before a fresh snapshot intent.
use crate::{Error, Fault, gate::Gate};
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::framing::{Accounting, Budget, Class, Limits, OwnedFrame, ReadStep};
use std::{
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
/// Aggregate metric without any URI, username, password, path or query parameter.
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum Metric {
    /// Actual current non-self CORE links.
    Connections = 0,
    /// Actual original admitted HTTP fetches.
    Downloads,
    /// Actual complete decoded HTTP body bytes.
    Bytes,
    /// Actual verified HELLOs, without address-authentication inference.
    Verified,
    /// Actual rejected HELLO/frame observations.
    Invalid,
    /// Actual complete local CORE advertisement payload writes.
    Advertisements,
    /// Actual HTTP request/response preparation count.
    Requests,
    /// Current published binary body size.
    PublishedBytes,
    /// Actual accepted learned URLs, not untested candidates.
    Learned,
    /// Historical current retry interval in milliseconds.
    RetryMillis,
    /// Actual successful original PEERSTORE store results.
    Stored,
    /// Actual failed fetch rounds.
    Failures,
}
const COUNT: usize = 12;
const NAMES: [&[u8]; COUNT] = [
    b"# active connections",
    b"# hostlist downloads initiated",
    b"# bytes downloaded from hostlist servers",
    b"# valid HELLOs downloaded from hostlist servers",
    b"# invalid HELLOs downloaded from hostlist servers",
    b"# hostlist advertisements send",
    b"hostlist requests processed",
    b"bytes in hostlist",
    b"# advertised hostlist URIs",
    b"# milliseconds between hostlist downloads",
    b"# HELLOs accepted by peerstore",
    b"# hostlist downloads failed",
];
/// Actual original STATISTICS local observations; no persistence ACK exists here.
#[derive(Debug)]
pub enum StatisticsEvent {
    /// Actual source attached.
    Connected(u64),
    /// Original immutable SET admitted to a local native queue.
    Queued {
        /// Actual original source serial.
        epoch: u64,
        /// Original sequence.
        sequence: u64,
        /// Bounded metric index, matching Metric.
        metric: usize,
        /// Exact absolute local value.
        value: u64,
    },
    /// Actual whole SET write only; no remote/durable processing is inferred.
    Written {
        /// Original source.
        epoch: u64,
        /// Original sequence.
        sequence: u64,
        /// Exact bounded metric index.
        metric: usize,
        /// Original immutable value.
        value: u64,
    },
    /// Actual original stream retired, with exact accepted prefix bytes.
    Retired {
        /// Original source serial.
        epoch: u64,
        /// Exact positive write prefix for its pending frame.
        bytes: usize,
        /// Actual source/error classification.
        reason: Fault,
    },
    /// Actual original native connection attempt failure.
    Retry(std::io::Error),
}
#[derive(Clone, Copy)]
struct Tag {
    epoch: u64,
    sequence: u64,
}
struct Pending {
    tag: Tag,
    metric: usize,
    value: u64,
    bytes: usize,
    gate: Gate,
}
pub(crate) struct Statistics {
    channel: Channel<Tag>,
    clock: std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    values: [u64; COUNT],
    dirty: u16,
    pending: Option<Pending>,
    epoch: u64,
    next: u64,
    attached: bool,
    closed: bool,
    until: u64,
    hard: Instant,
    operation: Duration,
    cursor: usize,
}
impl Statistics {
    pub fn new(
        source: EndpointSource,
        until: u64,
        hard: Instant,
        operation: Duration,
        io: usize,
    ) -> Result<Self, Error> {
        let clock = source.clock();
        let limits = Limits {
            frame_bytes: 65535,
            ordinary: Budget {
                frames: 1,
                bytes: 65535,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: io,
        };
        Ok(Self {
            channel: Channel::new(source, limits)?,
            clock,
            values: [0; COUNT],
            dirty: (1 << COUNT) - 1,
            pending: None,
            epoch: 0,
            next: 0,
            attached: false,
            closed: false,
            until,
            hard,
            operation,
            cursor: 0,
        })
    }
    pub fn set(&mut self, metric: Metric, value: u64) {
        let index = metric as usize;
        if self.values[index] != value {
            self.values[index] = value;
            self.dirty |= 1 << index;
        }
    }
    pub fn add(&mut self, metric: Metric, value: u64) {
        self.set(metric, self.values[metric as usize].saturating_add(value));
    }
    fn retire(&mut self, reason: Fault, observe: &mut impl FnMut(StatisticsEvent)) {
        self.channel.detach();
        self.attached = false;
        let bytes = self.pending.take().map_or(0, |p| p.bytes);
        observe(StatisticsEvent::Retired {
            epoch: self.epoch,
            bytes,
            reason,
        });
        // This is a fresh absolute snapshot intent of the present local counters,
        // never the retired source's immutable SET or an inferred ACK.
        self.dirty = (1 << COUNT) - 1;
    }
    pub fn close(&mut self, observe: &mut impl FnMut(StatisticsEvent)) {
        if !self.closed {
            self.retire(Fault::Closed, observe);
            self.channel.close();
            self.closed = true;
        }
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(StatisticsEvent),
    ) -> Poll<Result<(), Error>> {
        if self.closed {
            return Poll::Pending;
        }
        if Instant::now() >= self.hard || now >= self.until {
            self.close(observe);
            return Poll::Ready(Ok(()));
        }
        if let Some(pending) = &mut self.pending {
            match pending.gate.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.retire(Fault::Deadline, observe);
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(_)) => {}
            }
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(())) => {}
        }
        if !self.attached {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    self.epoch = self.epoch.checked_add(1).ok_or(Fault::Overflow)?;
                    self.attached = true;
                    observe(StatisticsEvent::Connected(self.epoch));
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                    observe(StatisticsEvent::Retry(error));
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    Poll::Ready(Err(error.into()))
                }
            };
        }
        if self.pending.is_none() && self.dirty != 0 {
            let index = (0..COUNT)
                .map(|offset| (self.cursor + offset) % COUNT)
                .find(|index| self.dirty & (1 << index) != 0)
                .ok_or(Fault::Stale)?;
            let next = self.next.checked_add(1).ok_or(Fault::Overflow)?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(256).map_err(|_| Fault::Capacity)?;
            bytes.resize(256, 0);
            let length = gnunet_client::statistics::Set {
                selector: gnunet_client::statistics::Selector {
                    subsystem: b"hostlist",
                    name: NAMES[index],
                },
                flags: gnunet_client::statistics::SET_PERSISTENT,
                value: self.values[index],
            }
            .encode(&mut bytes)?;
            bytes.truncate(length);
            let duration =
                u64::try_from(self.operation.as_micros()).map_err(|_| Fault::Overflow)?;
            let until = now.saturating_add(duration).min(self.until);
            let native_start = Instant::now();
            let mut gate = Gate::new(self.clock.clone(), until)?;
            gate.hard = gate.hard.min(self.hard).min(
                native_start
                    .checked_add(self.operation)
                    .ok_or(Fault::Overflow)?,
            );
            let tag = Tag {
                epoch: self.epoch,
                sequence: next,
            };
            self.channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .enqueue_owned(OwnedFrame::new(bytes), tag, Class::Ordinary)
                .map_err(|e| e.reason)?;
            self.pending = Some(Pending {
                tag,
                metric: index,
                value: self.values[index],
                bytes: 0,
                gate,
            });
            self.next = next;
            self.cursor = (index + 1) % COUNT;
            observe(StatisticsEvent::Queued {
                epoch: self.epoch,
                sequence: next,
                metric: index,
                value: self.values[index],
            });
            return Poll::Ready(Ok(()));
        }
        if self.pending.is_some() {
            match self
                .channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .poll_write(cx)
            {
                Poll::Ready(Ok(write)) => {
                    let pending = self.pending.as_mut().ok_or(Fault::Stale)?;
                    if write.origin.epoch != pending.tag.epoch
                        || write.origin.sequence != pending.tag.sequence
                    {
                        return Poll::Ready(Err(Fault::Stale.into()));
                    }
                    pending.bytes = pending
                        .bytes
                        .checked_add(write.bytes)
                        .ok_or(Fault::Overflow)?;
                    if write.complete {
                        let pending = self.pending.take().ok_or(Fault::Stale)?;
                        if self.values[pending.metric] == pending.value {
                            self.dirty &= !(1 << pending.metric)
                        }
                        observe(StatisticsEvent::Written {
                            epoch: pending.tag.epoch,
                            sequence: pending.tag.sequence,
                            metric: pending.metric,
                            value: pending.value,
                        })
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    self.retire(Fault::Io, observe);
                    return Poll::Ready(Err(error.into()));
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
            Poll::Ready(Ok(ReadStep::Eof)) => {
                self.retire(Fault::Closed, observe);
                self.channel.schedule_retry()?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.retire(Fault::Io, observe);
                Poll::Ready(Err(error.into()))
            }
            Poll::Ready(Ok(ReadStep::Progress { complete: true, .. })) => {
                self.retire(Fault::Malformed, observe);
                Poll::Ready(Err(Fault::Malformed.into()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}
