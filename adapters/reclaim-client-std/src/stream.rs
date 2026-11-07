//! Dedicated original-MQ iterator owner. No lost cursor reconnect/replay.
use crate::{
    Client, Control, EndpointSource, Epoch, Error, Instance, Limits, Loss, Operation, Progress,
    SecretKeyView, clock::RuntimeClock, ipc,
};
use gnunet_types::Error as Fault;
use std::{
    future::poll_fn,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;

/// One independent actual attribute, credential or ticket iterator MQ. The
/// original START/RID/key/frame cannot be rebound to a replacement source.
/// C ticket producers may push more items without NEXT; every item is nevertheless
/// delivered only from this same actual original source and in received order.
pub struct Iterator<'id> {
    client: Client<'id>,
    operation: Operation<'id>,
    kind: ipc::Iteration,
    finished: bool,
    close_report: Option<Loss<'id>>,
}
impl<'id> Iterator<'id> {
    /// Reserve a dedicated iterator and immutable START. Opens no socket until
    /// driven, starts no task/Resolver and copies no extra secret-key cache.
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        key: SecretKeyView<'_>,
        kind: ipc::Iteration,
        until: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        let (client, operation) = Client::stream_new(instance, source, key, kind, until, limits)?;
        Ok(Self {
            client,
            operation,
            kind,
            finished: false,
            close_report: None,
        })
    }
    /// Exact original private Rust operation allocation.
    #[must_use]
    pub const fn operation(&self) -> Operation<'id> {
        self.operation
    }
    /// Exact official original RID, not a private allocation serial.
    pub fn request_id(&self) -> Result<u32, Error> {
        self.client.request_id(self.operation)
    }
    /// Exact independent iterator family.
    #[must_use]
    pub const fn kind(&self) -> ipc::Iteration {
        self.kind
    }
    /// Actual original attached source, absent before attach/after physical loss.
    #[must_use]
    pub fn epoch(&self) -> Option<Epoch<'id>> {
        self.client.epoch()
    }
    /// The shared canonical clock supplied with this exact endpoint source.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.client.clock()
    }
    /// Locally written START/NEXT item grants not yet consumed, at most1.
    /// This is not a remote ACK or strict ticket push limit: active C ticket
    /// iteration advances automatically and can produce additional real items.
    #[must_use]
    pub fn credit(&self) -> u64 {
        self.client.credit()
    }
    /// Prepare one real immutable NEXT on the original MQ. At most one control
    /// and one unused requested item grant are retained. Deadlines are capped
    /// by the original iterator's canonical AND native hard boundaries.
    pub fn next(&mut self, until: u64) -> Result<Control<'id>, Error> {
        if self.finished {
            return Err(Fault::Closed.into());
        }
        self.client.stream_next(until)
    }
    /// Prepare actual STOP on the original MQ. A zero-exposure START is instead
    /// physically closed and returns None. A pending NEXT returns WouldBlock;
    /// drive it or close this source explicitly. STOP has no service ACK.
    pub fn stop(&mut self, until: u64) -> Result<Option<Control<'id>>, Error> {
        if self.finished {
            return Err(Fault::Closed.into());
        }
        self.client.stream_stop(until)
    }
    /// Physically stop this original owner without sampling any clock. Local
    /// terminal outcomes stay drainable; no ticket revocation/rollback is implied.
    pub fn close(&mut self) -> Option<Loss<'id>> {
        let result = self.client.close();
        if self.close_report.is_none() {
            self.close_report = result
        }
        result
    }
    /// Take exact original physical-stop accounting, including pending control
    /// exposure. Channel drops its socket; it does not expose close errno, so
    /// this is neither a kernel-close-error receipt nor a remote STOP ACK.
    pub fn take_close_report(&mut self) -> Option<Loss<'id>> {
        self.close_report
            .take()
            .or_else(|| self.client.take_control_close())
    }
    /// Poll one bounded native step. Canceling a wait preserves original RX/TX
    /// cursors. Actual terminal response/local completion closes this MQ BEFORE
    /// exposing its completion. No iterator snapshot/cursor is silently replayed.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if self.finished {
            return Poll::Ready(Ok(Progress::Closed));
        }
        match self.client.poll(cx, until) {
            Poll::Ready(Ok(Progress::Completed(c))) => {
                let reported = self.client.take_control_close();
                let physical = self.close();
                if self.close_report.is_none() {
                    self.close_report = reported.or(physical)
                }
                self.finished = true;
                if c.operation != self.operation {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                Poll::Ready(Ok(Progress::Completed(c)))
            }
            Poll::Ready(Err(error)) => {
                let _loss = self.close();
                self.finished = true;
                Poll::Ready(Err(error))
            }
            other => other,
        }
    }
    /// Caller-driven wrapper, with an observation-only wait deadline.
    pub async fn drive(&mut self, until: Option<Instant>) -> Result<Progress<'id>, Error> {
        poll_fn(|cx| self.poll(cx, until)).await
    }
}
