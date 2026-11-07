//! Independent official iterator/monitor MQ owners sharing the bounded driver.
use crate::{
    Client, Control, EndpointSource, Epoch, Error, Instance, Limits, Loss, Operation, Progress,
    SecretKey, clock::RuntimeClock,
};
use gnunet_types::Error as Fault;
use std::{
    future::poll_fn,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;
struct Subscription<'id> {
    client: Client<'id>,
    operation: Operation<'id>,
    finished: bool,
    close_report: Option<Loss<'id>>,
}
impl<'id> Subscription<'id> {
    fn close(&mut self) -> Option<Loss<'id>> {
        let result = self.client.close();
        if self.close_report.is_none() {
            self.close_report = result;
        }
        result
    }
    fn settle(&mut self, result: Result<Progress<'id>, Error>) -> Result<Progress<'id>, Error> {
        match result {
            Ok(Progress::Completed(c)) => {
                let reported = self.client.take_control_close();
                let physical = self.close();
                if self.close_report.is_none() {
                    self.close_report = reported.or(physical);
                }
                self.finished = true;
                if c.operation != self.operation {
                    return Err(Fault::StaleGeneration.into());
                }
                Ok(Progress::Completed(c))
            }
            Err(error) => {
                let _loss = self.close();
                self.finished = true;
                Err(error)
            }
            other => other,
        }
    }
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress<'id>>, Error> {
        if self.finished {
            return Ok(None);
        }
        let Some(event) = self.client.poll_native_guard(cx) else {
            return Ok(None);
        };
        self.settle(Ok(event)).map(Some)
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if self.finished {
            return Poll::Ready(Ok(Progress::Closed));
        }
        match self.client.poll(cx, until) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(self.settle(result)),
        }
    }
}
/// A dedicated actual zone-iterator MQ. It never replays a lost cursor. Natural
/// completion is the actual END response, distinct from a local STOP write.
pub struct ZoneIterator<'id> {
    inner: Subscription<'id>,
}
/// A dedicated actual monitor MQ. It never pretends to preserve a snapshot
/// across loss; construct a fresh owner to request an explicit fresh snapshot.
pub struct Monitor<'id> {
    inner: Subscription<'id>,
}
impl<'id> ZoneIterator<'id> {
    /// Start a real filtered iterator. None selects all zones; the initial one
    /// result credit becomes usable only after the original START whole write.
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        zone: Option<&SecretKey>,
        filter: u16,
        until: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        let (client, operation) =
            Client::stream_new(instance, source, zone, filter, None, until, limits)?;
        Ok(Self {
            inner: Subscription {
                client,
                operation,
                finished: false,
                close_report: None,
            },
        })
    }
    /// Prepare the actual original iterator STOP. Unsent START can be removed
    /// and physically closed without a STOP. A pending NEXT returns WouldBlock;
    /// drive it first or close the actual source. STOP has no server ACK.
    pub fn stop(&mut self, until: u64) -> Result<Option<Control<'id>>, Error> {
        if self.inner.finished {
            return Err(Fault::Closed.into());
        }
        self.inner.client.stream_stop(until)
    }
}
impl<'id> Monitor<'id> {
    /// Start a real monitor. SYNC is delivered only from the actual source; it
    /// consumes no credit. Private returned zone keys remain opaque/redacted.
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        zone: Option<&SecretKey>,
        iterate_first: bool,
        filter: u16,
        until: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        let (client, operation) = Client::stream_new(
            instance,
            source,
            zone,
            filter,
            Some(iterate_first),
            until,
            limits,
        )?;
        Ok(Self {
            inner: Subscription {
                client,
                operation,
                finished: false,
                close_report: None,
            },
        })
    }
    /// True only after actual original SYNC on a still-live source.
    #[must_use]
    pub fn synchronized(&self) -> bool {
        self.inner.client.synchronized()
    }
    /// Stop the actual monitor MQ without sampling a clock. No monitor STOP or
    /// RPC CANCEL exists on wire, and source close is no rollback acknowledgement.
    pub fn stop(&mut self) -> Option<Loss<'id>> {
        self.inner.close()
    }
}
macro_rules! common {
    ($name:ident) => {
        impl<'id> $name<'id> {
            /// Original private Rust operation, never a synthesized wire field.
            #[must_use]
            pub const fn operation(&self) -> Operation<'id> {
                self.inner.operation
            }
            /// Exact actual source, absent before attach or after physical retirement.
            #[must_use]
            pub fn epoch(&self) -> Option<Epoch<'id>> {
                self.inner.client.epoch()
            }
            /// Shared canonical clock. Cloning starts no source/listener/Resolver.
            #[must_use]
            pub fn clock(&self) -> Arc<dyn RuntimeClock> {
                self.inner.client.clock()
            }
            /// Current live granted record credits. SYNC and END consume none.
            #[must_use]
            pub fn credit(&self) -> u64 {
                self.inner.client.credit()
            }
            /// Prepare one finite actual NEXT after START whole write. Added credit is
            /// bounded and becomes effective only on this immutable control's full write.
            /// Its deadline is capped by the original stream's deadline, never renewed.
            pub fn next(&mut self, limit: u64, until: u64) -> Result<Control<'id>, Error> {
                if self.inner.finished {
                    return Err(Fault::Closed.into());
                }
                self.inner.client.stream_next(limit, until)
            }
            /// Check/arm only original native bounds before an enclosing clock wait.
            /// No socket IO or logical sampling occurs. Any terminal stream outcome
            /// physically closes its original dedicated MQ before it is exposed,
            /// exactly as ordinary poll does; no source or cursor is replayed.
            pub fn poll_native_guard(
                &mut self,
                cx: &mut Context<'_>,
            ) -> Result<Option<Progress<'id>>, Error> {
                self.inner.poll_native_guard(cx)
            }
            /// Poll one original bounded source step. Canceling its future retains the
            /// original partial cursors. Terminal completion physically closes this MQ
            /// before exposing END/local outcome; no cursor is silently reconnected.
            pub fn poll(
                &mut self,
                cx: &mut Context<'_>,
                until: Option<Instant>,
            ) -> Poll<Result<Progress<'id>, Error>> {
                self.inner.poll(cx, until)
            }
            /// Caller-driven wrapper; creates no hidden task/thread or Resolver.
            pub async fn drive(&mut self, until: Option<Instant>) -> Result<Progress<'id>, Error> {
                poll_fn(|cx| self.poll(cx, until)).await
            }
            /// Stop the actual owner independently of clock health. Terminal local
            /// observations remain available to poll; this grants no database rollback.
            pub fn close(&mut self) -> Option<Loss<'id>> {
                self.inner.close()
            }
            /// Take the exact physical-stop accounting, including any original pending
            /// control's real byte exposure. It is not a kernel close/remote ACK receipt.
            pub fn take_close_report(&mut self) -> Option<Loss<'id>> {
                self.inner
                    .close_report
                    .take()
                    .or_else(|| self.inner.client.take_control_close())
            }
        }
    };
}
common!(ZoneIterator);
common!(Monitor);
