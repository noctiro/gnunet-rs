//! Original application listener MQ and callback-scoped accept/reject.
use crate::{Bounds, Cause, Epoch, Error, Limits, OperationType, Prepared, ResultMode};
use crate::{
    prepared::{Acceptance, Plan},
    session::{Session, Step, TransportLoss},
    types::Owner,
};
use gnunet_client_host::EndpointSource;
use gnunet_types::Error as Fault;
use gnunet_wire::official::set::{ClientRequest, ClientResponse, Options};
use std::{
    future::poll_fn,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Instant,
};
/// Borrowed original request; acceptance decision is made in this callback only.
pub struct Incoming<'a> {
    /// Actual original listening source.
    pub epoch: &'a Epoch,
    /// Actual peer identity carried by the original request.
    pub peer: [u8; 32],
    /// Exact optional nested application message.
    pub context: &'a [u8],
}

#[cfg(all(test, unix))]
mod reject_tests;
/// Callback-local decision. Accept only prepares; Set::commit starts the exchange.
pub enum Decision {
    /// Queue the original request's rejection; no processing ACK exists.
    Reject,
    /// Prepare the original accept correlation for a later real Set commit.
    Accept {
        /// Selected public result mode.
        mode: ResultMode,
        /// Original option bytes.
        options: Options,
    },
}
/// Exact original accepted request whose rejection is now queued. Retaining
/// this token preserves the listener epoch/accept-id association until its
/// actual whole write or original listener retirement; queueing is not an ACK.
pub struct RejectId {
    acceptance: Arc<Acceptance>,
}
impl RejectId {
    /// Match only a write callback from this exact original physical listener.
    #[must_use]
    pub fn matches(&self, epoch: &Epoch, accept_id: u32) -> bool {
        self.acceptance.epoch == *epoch && self.acceptance.accept_id == accept_id
    }
}
/// Refused rejection admission returns the same unique uncommitted preparation.
pub struct RejectFailure {
    /// Original native/domain/capacity failure.
    pub error: Error,
    /// Original preparation, still available for retry or actual source close.
    pub prepared: Prepared,
}
/// Original listener loss and independent reconnect-admission outcome.
pub struct ListenerLoss {
    /// Actual refusing bound/check; absent for ordinary source/provider failures.
    pub deadline: Option<Box<crate::DeadlineContext>>,
    /// Actual original source prefix/debt facts, captured before retirement.
    pub transport: TransportLoss,
    /// Original cause, not replaced by reconnect/cleanup failure.
    pub cause: Cause,
    /// True only when the same original read-only intent can next reconnect.
    pub will_retry: bool,
    /// Independent local retry-admission failure, when present.
    pub retry_error: Option<Error>,
}
/// Actual listener progress; no event grants a service/peer processing ACK.
pub enum ListenProgress {
    /// A new physical MQ attached; Listen has not necessarily written.
    Attached(Epoch),
    /// Original syscall attempt failed before registration.
    Retry(std::io::Error),
    /// Actual positive bytes on original Listen or Reject frame.
    Written {
        /// Original physical source.
        epoch: Epoch,
        /// None means Listen initializer; Some is original rejected accept id.
        rejected: Option<u32>,
        /// Actual bytes this syscall.
        bytes: usize,
        /// Actual whole frame written, not service acceptance.
        complete: bool,
    },
    /// Local prepared acceptance, with no operation started until commit.
    Accepted(Prepared),
    /// Original Reject admitted to the native queue, not yet whole-written.
    RejectQueued,
    /// Bounded native cursor/input progress.
    Activity,
    /// Original MQ retired before any replacement.
    Lost(ListenerLoss),
}
/// One actual application listener. Its immutable original deadline spans retries.
pub struct Listener {
    session: Session<u32>,
    domain: Owner,
    operation: OperationType,
    limits: Limits,
    accepted: Vec<Weak<Acceptance>>,
    recover_reject: Option<u32>,
    closed: bool,
}
impl Listener {
    /// Reject one actual still-uncommitted incoming preparation on its original
    /// listener. Evaluate plans, foreign factories/listeners and retired epochs
    /// cannot authorize this action. Failure returns the unchanged owner; a
    /// successful return proves queue admission only, never a whole write.
    pub fn reject_prepared(&mut self, prepared: Prepared) -> Result<RejectId, RejectFailure> {
        let result = (|| -> Result<(), Error> {
            let Plan::Accept(acceptance) = &prepared.plan else {
                return Err(Fault::InvalidInput.into());
            };
            if self.closed
                || !Arc::ptr_eq(&self.domain, &acceptance.domain)
                || self.operation != acceptance.operation
                || self.session.epoch() != Some(&acceptance.epoch)
                || !acceptance.epoch.live()
            {
                return Err(Fault::Stale.into());
            }
            self.session.check()?;
            let bytes = crate::encode(ClientRequest::Reject {
                accept_id: acceptance.accept_id,
            })?;
            let bound = self.session.phase()?;
            self.session
                .enqueue(bytes, acceptance.accept_id, bound, true)
        })();
        if let Err(error) = result {
            return Err(RejectFailure { error, prepared });
        }
        match prepared {
            Prepared {
                plan: Plan::Accept(acceptance),
                ..
            } => Ok(RejectId { acceptance }),
            // Validation above only admits Accept; retain the full owner even
            // in this defensive branch rather than substituting another plan.
            prepared => Err(RejectFailure {
                error: Fault::InvalidInput.into(),
                prepared,
            }),
        }
    }
    pub(crate) fn new(
        source: EndpointSource,
        domain: Owner,
        operation: OperationType,
        app_id: [u8; 64],
        limits: Limits,
        bounds: Bounds,
    ) -> Result<Self, Error> {
        if operation == OperationType::Local {
            return Err(Fault::Unsupported.into());
        }
        let bytes = crate::encode(ClientRequest::Listen {
            operation: operation as u32,
            app_id,
        })?;
        Ok(Self {
            session: Session::new(source, bytes, limits, bounds)?,
            domain,
            operation,
            limits,
            accepted: Vec::new(),
            recover_reject: None,
            closed: false,
        })
    }
    fn lost(&mut self, cause: Cause, retry: bool) -> ListenerLoss {
        let transport = self.session.retire(!retry);
        self.recover_reject = None;
        self.accepted.clear();
        let retry_error = if retry {
            self.session.retry().err()
        } else {
            None
        };
        let will_retry = retry && retry_error.is_none();
        if !will_retry {
            self.closed = true;
            if retry {
                let _actual = self.session.retire(true);
            }
        }
        ListenerLoss {
            deadline: None,
            transport,
            cause,
            will_retry,
            retry_error,
        }
    }
    fn failed(&mut self, error: Error, retry: bool) -> ListenerLoss {
        let (cause, deadline) = error.into_cause_parts();
        let mut loss = self.lost(cause, retry);
        loss.deadline = deadline;
        loss
    }
    /// Physically close first, then invalidate all uncommitted original accepts.
    /// This clock-free action never registers a new listener.
    pub fn close(&mut self) -> ListenerLoss {
        self.lost(Cause::Requested, false)
    }
    /// Original overall native bound, without a source/operation token.
    #[must_use]
    pub fn native_deadline(&self) -> Instant {
        self.session.original().hard
    }
    /// Clock-free deadline fence for a caller waiting on unrelated output.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<ListenerLoss> {
        if self.closed {
            return None;
        }
        self.session
            .native_expired(cx)
            .map(|context| self.failed(Error::deadline(context), false))
    }
    fn reject(&mut self, id: u32) -> Result<ListenProgress, Error> {
        let bytes = crate::encode(ClientRequest::Reject { accept_id: id })?;
        let bound = self.session.phase()?;
        self.session.enqueue(bytes, id, bound, true)?;
        self.recover_reject = None;
        Ok(ListenProgress::RejectQueued)
    }
    fn frame(
        &mut self,
        epoch: Epoch,
        bytes: &[u8],
        decide: &mut impl FnMut(Incoming<'_>) -> Decision,
    ) -> Result<ListenProgress, Error> {
        let ClientResponse::Request {
            accept_id,
            peer,
            context,
        } = ClientResponse::decode(bytes, self.limits.abi)?
        else {
            return Err(Fault::Malformed.into());
        };
        self.accepted.retain(|x| x.strong_count() > 0);
        if self
            .accepted
            .iter()
            .filter_map(Weak::upgrade)
            .any(|a| a.accept_id == accept_id && a.epoch == epoch)
        {
            return Err(Fault::Malformed.into());
        }
        // If a callback unwinds and is caught, the next poll rejects this exact
        // original id before reading any new request; no IO occurs from Drop.
        self.recover_reject = Some(accept_id);
        let decision = decide(Incoming {
            epoch: &epoch,
            peer,
            context,
        });
        self.session.check()?;
        match decision {
            Decision::Reject => self.reject(accept_id),
            Decision::Accept { mode, options } => {
                if self.accepted.len() >= self.limits.operations {
                    return Err(Fault::Capacity.into());
                }
                self.accepted.try_reserve(1).map_err(|_| Fault::Capacity)?;
                let accepted = Arc::new(Acceptance {
                    domain: self.domain.clone(),
                    epoch,
                    operation: self.operation,
                    accept_id,
                });
                self.accepted.push(Arc::downgrade(&accepted));
                self.recover_reject = None;
                Ok(ListenProgress::Accepted(Prepared {
                    mode,
                    options,
                    plan: Plan::Accept(accepted),
                }))
            }
        }
    }
    /// Poll this original MQ. Callback borrows remain valid only during this call.
    /// Native loss is exposed before a replacement epoch can register Listen.
    pub fn poll_progress(
        &mut self,
        cx: &mut Context<'_>,
        decide: &mut impl FnMut(Incoming<'_>) -> Decision,
    ) -> Poll<Result<ListenProgress, Error>> {
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        if let Some(loss) = self.poll_native_guard(cx) {
            return Poll::Ready(Ok(ListenProgress::Lost(loss)));
        }
        if let Some(id) = self.recover_reject {
            return Poll::Ready(match self.reject(id) {
                Ok(p) => Ok(p),
                Err(e) => Ok(ListenProgress::Lost(self.failed(e, false))),
            });
        }
        let step = match self.session.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(s)) => s,
            Poll::Ready(Err(error)) => {
                let retry = matches!(&error, Error::Io(_));
                return Poll::Ready(Ok(ListenProgress::Lost(self.failed(error, retry))));
            }
        };
        let result = match step {
            Step::Attached(e) => Ok(ListenProgress::Attached(e)),
            Step::Retry(e) => Ok(ListenProgress::Retry(e)),
            Step::Written {
                epoch,
                tag,
                bytes,
                complete,
            } => Ok(ListenProgress::Written {
                epoch,
                rejected: tag,
                bytes,
                complete,
            }),
            Step::Activity => Ok(ListenProgress::Activity),
            Step::Eof => return Poll::Ready(Ok(ListenProgress::Lost(self.lost(Cause::Eof, true)))),
            Step::Frame { epoch, bytes } => self.frame(epoch, &bytes, decide),
        };
        Poll::Ready(match result {
            Ok(p) => Ok(p),
            Err(e) => Ok(ListenProgress::Lost(self.failed(e, false))),
        })
    }
    /// Await only this owner; dropping the future retains cursors/deadlines.
    pub async fn progress(
        &mut self,
        decide: &mut impl FnMut(Incoming<'_>) -> Decision,
    ) -> Result<ListenProgress, Error> {
        poll_fn(|cx| self.poll_progress(cx, decide)).await
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        let _actual = self.close();
    }
}
