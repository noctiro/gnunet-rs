//! Fixed relay directory with fair polling and independently retained failures.
use super::{RejectedRelay, RelayLimits, RelayProgress, RelayReport, TcpRelay, TcpUpstream};
use gnunet_native::dns_proxy::{FlowId, TcpFlow};
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

/// One bounded original relay outcome.
#[derive(Debug)]
pub enum RelayPoolProgress {
    /// One original operation progressed.
    Activity,
    /// One original flow and its upstream retired; the complete report is retained.
    Finished {
        /// Non-reused native flow identity.
        flow: FlowId,
        /// Actual local operation and independent retirement observations.
        report: RelayReport,
    },
    /// Only caller wait budget ended.
    WaitDeadline,
    /// Closed pool has no original relays or callback debts left.
    Stopped,
}
/// Fixed original flow directory; each relay keeps its own bounded buffers and I/O.
pub struct RelayPool {
    relays: Vec<Option<TcpRelay>>,
    limits: RelayLimits,
    cursor: usize,
    closing: bool,
    timer: Pin<Box<Sleep>>,
}
impl RelayPool {
    /// Reserve metadata only; no native flow or network connection is opened.
    /// # Errors
    /// Refuses zero/overflowing capacity, invalid bounds or directory allocation failure.
    /// # Panics
    /// Requires an entered Tokio runtime with time enabled.
    pub fn new(capacity: usize, limits: RelayLimits) -> io::Result<Self> {
        limits.validate(Instant::now())?;
        if capacity == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        capacity
            .checked_mul(limits.buffer_bytes)
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut relays = Vec::new();
        relays
            .try_reserve_exact(capacity)
            .map_err(|_| io::Error::other("TCP relay directory allocation refused"))?;
        relays.resize_with(capacity, || None);
        Ok(Self {
            relays,
            limits,
            cursor: 0,
            closing: false,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
        })
    }
    /// Adopt both original owners once; no fallback upstream is constructed.
    /// # Errors
    /// Returns both owners on full/closed directory or invalid original relay pairing.
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns both original native and upstream owners for explicit retirement"
    )]
    pub fn admit(&mut self, flow: TcpFlow, upstream: TcpUpstream) -> Result<FlowId, RejectedRelay> {
        let slot = if self.closing {
            None
        } else {
            self.relays.iter().position(Option::is_none)
        };
        let Some(slot) = slot else {
            return Err(RejectedRelay {
                error: if self.closing {
                    io::ErrorKind::NotConnected
                } else {
                    io::ErrorKind::WouldBlock
                }
                .into(),
                flow,
                upstream,
            });
        };
        let id = flow.id();
        let relay = TcpRelay::new(flow, upstream, self.limits)?;
        self.relays[slot] = Some(relay);
        Ok(id)
    }
    /// Whether one more original flow can be admitted without evicting another.
    pub fn has_capacity(&self) -> bool {
        !self.closing && self.relays.iter().any(Option::is_none)
    }
    /// Request close on each original relay without releasing callback loans.
    pub fn close(&mut self) {
        self.closing = true;
        for relay in self.relays.iter_mut().flatten() {
            relay.close();
        }
    }
    /// Drive existing owners fairly; canceling the waiter changes no operation.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<RelayPoolProgress> {
        let capacity = self.relays.len();
        for offset in 0..capacity {
            let slot = (self.cursor + offset) % capacity;
            let Some(relay) = &mut self.relays[slot] else {
                continue;
            };
            match relay.poll(cx, until) {
                Poll::Ready(RelayProgress::Stopped) => {
                    let flow = relay.id();
                    let Some(relay) = self.relays[slot].take() else {
                        continue;
                    };
                    self.cursor = (slot + 1) % capacity;
                    return Poll::Ready(RelayPoolProgress::Finished {
                        flow,
                        report: relay.into_report(),
                    });
                }
                Poll::Ready(RelayProgress::Activity) => {
                    self.cursor = (slot + 1) % capacity;
                    return Poll::Ready(RelayPoolProgress::Activity);
                }
                _ => {}
            }
        }
        if self.closing && self.relays.iter().all(Option::is_none) {
            return Poll::Ready(RelayPoolProgress::Stopped);
        }
        if let Some(until) = until {
            if Instant::now() >= until {
                return Poll::Ready(RelayPoolProgress::WaitDeadline);
            }
            self.timer.as_mut().reset(until);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    /// Wait without spawning a worker or discarding an original partial cursor.
    pub async fn drive(&mut self, until: Option<Instant>) -> RelayPoolProgress {
        poll_fn(|cx| self.poll(cx, until)).await
    }
}
impl Drop for RelayPool {
    fn drop(&mut self) {
        self.close();
    }
}
