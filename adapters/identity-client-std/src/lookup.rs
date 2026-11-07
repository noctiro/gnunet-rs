//! Explicit independent one-shot exact/suffix lookup MQs.
use crate::{
    Client, Completion, EndpointSource, Epoch, Error, Identity, Instance, Kind, Limits,
    LocalReason, Loss, Operation, Outcome, Progress, Submission,
};
use gnunet_types::Error as Fault;
use std::{
    fmt,
    future::poll_fn,
    task::{Context, Poll},
};
use tokio::time::Instant;
/// Actual original lookup result. No missing/default ego is synthesized locally.
pub enum LookupOutcome {
    /// Actual UPDATE on this exact original lookup MQ.
    Found(Identity),
    /// Actual RESULT_CODE on the original lookup MQ. The pinned service uses200
    /// for missing names. Unknown codes are preserved instead of being guessed.
    ResultCode(u32),
    /// Local retirement; exposed requests may still have run, without a result.
    Local {
        /// Original local reason.
        reason: LocalReason,
        /// Actual native request exposure.
        submission: Submission,
        /// Actual late service result observed before local retirement.
        result_code: Option<u32>,
    },
}
impl fmt::Debug for LookupOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Found(_) => f.write_str("Found([REDACTED])"),
            Self::ResultCode(code) => f.debug_tuple("ResultCode").field(code).finish(),
            Self::Local {
                reason,
                submission,
                result_code,
            } => f
                .debug_struct("Local")
                .field("reason", reason)
                .field("submission", submission)
                .field("result_code", result_code)
                .finish(),
        }
    }
}
/// One original source observation or terminal lookup outcome.
#[derive(Debug)]
pub enum LookupProgress<'id> {
    /// Actual source/admission/write/partial/loss observation. A Completed event
    /// is converted to Finished and never appears inside this variant.
    Source(Progress<'id>),
    /// Original result frozen, original physical MQ already stopped. This is
    /// independent of any later fresh lookup or monitor allocation.
    Finished {
        /// Original Rust operation, never a wire RID.
        operation: Operation<'id>,
        /// Actual original native source if one attached.
        epoch: Option<Epoch<'id>>,
        /// Actual response or local retirement.
        outcome: LookupOutcome,
    },
    /// Terminal result already delivered.
    Closed,
}
/// One explicitly allocated dedicated lookup source. No lookup is replayed on
/// loss. Exact and suffix requests preserve the service's own name semantics.
pub struct Lookup<'id> {
    client: Client<'id>,
    operation: Operation<'id>,
    ended: bool,
}
impl<'id> Lookup<'id> {
    /// Exact official lookup, selected by the real service (case-insensitive in
    /// the pinned implementation). Constructing opens no socket and no task.
    pub fn exact(
        instance: &'id Instance,
        source: EndpointSource,
        name: &[u8],
        until: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(instance, source, name, false, until, limits)
    }
    /// Official longest dot-boundary suffix lookup. The pinned service uses a
    /// case-sensitive suffix comparison; this client does not rewrite names.
    pub fn by_suffix(
        instance: &'id Instance,
        source: EndpointSource,
        name: &[u8],
        until: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(instance, source, name, true, until, limits)
    }
    fn new(
        instance: &'id Instance,
        source: EndpointSource,
        name: &[u8],
        suffix: bool,
        until: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        let (client, operation) = Client::lookup(instance, source, name, suffix, until, limits)?;
        Ok(Self {
            client,
            operation,
            ended: false,
        })
    }
    /// Original lookup operation identity.
    #[must_use]
    pub const fn operation(&self) -> Operation<'id> {
        self.operation
    }
    /// Actual source identity if attached and not retired.
    #[must_use]
    pub fn epoch(&self) -> Option<Epoch<'id>> {
        self.client.epoch()
    }
    /// Physically stop the original MQ without sampling a clock. There is no
    /// official wire CANCEL and this is no remote cancellation acknowledgement.
    /// A local canceled completion remains available to drive/poll.
    pub fn cancel(&mut self) -> Result<Option<Loss<'id>>, Error> {
        if self.ended {
            return Ok(None);
        }
        self.client.cancel(self.operation)?;
        Ok(self.client.close())
    }
    /// Independently close the native owner on every error/shutdown path. No
    /// close errno evidence is invented when the shared transport supplies none.
    pub fn close(&mut self) -> Option<Loss<'id>> {
        if self.ended {
            None
        } else {
            self.client.close()
        }
    }
    fn finish(&mut self, completion: Completion<'id>) -> Result<LookupProgress<'id>, Error> {
        // Always physically stop first, including malformed original metadata.
        let _loss = self.client.close();
        self.ended = true;
        if completion.operation != self.operation
            || !matches!(completion.kind, Kind::Lookup | Kind::LookupSuffix)
        {
            return Err(Fault::StaleGeneration.into());
        }
        let outcome = match completion.outcome {
            Outcome::Found(identity) => LookupOutcome::Found(identity),
            Outcome::Result {
                code,
                created: None,
            } => LookupOutcome::ResultCode(code),
            Outcome::Local {
                reason,
                submission,
                result_code,
                creation_material: None,
            } => LookupOutcome::Local {
                reason,
                submission,
                result_code,
            },
            _ => return Err(Fault::Conflict.into()),
        };
        Ok(LookupProgress::Finished {
            operation: completion.operation,
            epoch: completion.epoch,
            outcome,
        })
    }
    /// Preserve the original native lookup/drain bounds while another source
    /// gates normal IO. A terminal completion physically closes this MQ before
    /// exposure, exactly as ordinary poll; no clock sample or IO is performed.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Result<Option<LookupProgress<'id>>, Error> {
        if self.ended {
            return Ok(None);
        }
        let Some(event) = self.client.poll_native_guard(cx) else {
            return Ok(None);
        };
        match event {
            Progress::Completed(completion) => self.finish(completion).map(Some),
            event => Ok(Some(LookupProgress::Source(event))),
        }
    }
    /// Poll the actual original source. Observation timeout never cancels the
    /// lookup; its original finite operation deadline and drain remain in force.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<LookupProgress<'id>, Error>> {
        if self.ended {
            return Poll::Ready(Ok(LookupProgress::Closed));
        }
        match self.client.poll(cx, until) {
            Poll::Ready(Ok(Progress::Completed(completion))) => {
                Poll::Ready(self.finish(completion))
            }
            Poll::Ready(Ok(event)) => Poll::Ready(Ok(LookupProgress::Source(event))),
            Poll::Ready(Err(error)) => {
                let _loss = self.client.close();
                self.ended = true;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    /// Caller-driven original-MQ wrapper. Canceling this future keeps retained
    /// partial cursors; call cancel/close or drop the owner to stop that source.
    pub async fn drive(&mut self, until: Option<Instant>) -> Result<LookupProgress<'id>, Error> {
        poll_fn(|cx| self.poll(cx, until)).await
    }
}
