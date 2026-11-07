//! Actual official PEERSTORE HELLO-add helper ownership. The existing helper
//! performs original scan/retirement/REPLACE, preserving newer verified HELLOs.
//! One compiler-pinned owned future retains the actual borrowed helper/client;
//! no detached task, self-reference, private backend or fabricated receipt.
use crate::Failure;
use gnunet_client_host::EndpointSource;
use gnunet_peerstore_client_host::{
    self as ps,
    hello::{self as api, AddProgress, HelloAdd},
};
use gnunet_types::{Error as Fault, Rejected};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};
type Observer<'id> = Box<dyn FnMut(&ps::Progress<'id>) + 'id>;
/// Original actual service result; StoreResult1 remains an API receipt only.
pub struct Finished<'id, J> {
    /// Original Pils/source/publication metadata.
    pub origin: J,
    /// Actual authoritative/local helper result and original MQ IDs.
    pub result: Result<api::Completion<'id>, ps::Error>,
}
struct Returned<'id, J> {
    client: ps::Client<'id>,
    finished: Finished<'id, J>,
    observe: Box<dyn FnMut(&ps::Progress<'id>) + 'id>,
}
type Running<'id, J> = Pin<Box<dyn Future<Output = Returned<'id, J>> + 'id>>;
/// At most one real HELLO-add, one owned client and bounded public scratch.
pub struct HelloSink<'id, J> {
    client: Option<ps::Client<'id>>,
    running: Option<Running<'id, J>>,
    observe: Option<Observer<'id>>,
    closed: bool,
    stopping: Arc<AtomicBool>,
    retired: Option<Finished<'id, J>>,
}
impl<'id, J: 'id> HelloSink<'id, J> {
    /// Construct one explicit existing general CLIENT with no hidden Resolver.
    /// Observer receives actual native facts; it must be bounded/nonblocking.
    pub fn new(
        instance: &'id mut ps::Instance,
        source: EndpointSource,
        limits: ps::Limits,
        observe: impl FnMut(&ps::Progress<'id>) + 'id,
    ) -> Result<Self, Failure> {
        let client = ps::Client::new(instance, source, limits)?;
        Ok(Self {
            client: Some(client),
            running: None,
            observe: Some(Box::new(observe)),
            closed: false,
            stopping: Arc::new(AtomicBool::new(false)),
            retired: None,
        })
    }
    /// Whether another original input can be admitted, not a service ACK.
    pub fn idle(&self) -> bool {
        !self.closed
            && self.running.is_none()
            && self.client.as_ref().is_some_and(ps::Client::is_idle)
    }
    /// Hand one immutable complete ordinary HELLO frame to the actual public
    /// helper. Same original native/UTC targets survive every later poll/retry.
    pub fn start(
        &mut self,
        origin: J,
        frame: Vec<u8>,
        options: api::Options,
    ) -> Result<(), Rejected<(J, Vec<u8>)>> {
        if !self.idle() {
            return Err(Rejected {
                value: (origin, frame),
                reason: if self.closed {
                    Fault::Closed
                } else {
                    Fault::WouldBlock
                },
            });
        }
        let mut scratch = Vec::new();
        if scratch
            .try_reserve_exact(options.hello.maximum_address_bytes)
            .is_err()
        {
            return Err(Rejected {
                value: (origin, frame),
                reason: Fault::Capacity,
            });
        }
        scratch.resize(options.hello.maximum_address_bytes, 0);
        let Some(mut client) = self.client.take() else {
            return Err(Rejected {
                value: (origin, frame),
                reason: Fault::NotReady,
            });
        };
        let Some(mut observe) = self.observe.take() else {
            self.client = Some(client);
            return Err(Rejected {
                value: (origin, frame),
                reason: Fault::NotReady,
            });
        };
        // The future owns client/scratch and the compiler pins its internal
        // borrow across polls. Dropping only a poll wait never drops this owner.
        let stopping = self.stopping.clone();
        self.running = Some(Box::pin(async move {
            let result = if stopping.load(Ordering::Acquire) {
                match client.close() {
                    Ok(_) => Err(Fault::Cancelled.into()),
                    Err(error) => Err(error),
                }
            } else {
                match HelloAdd::start(&mut client, &frame, &mut scratch, options) {
                    Err(error) => Err(error),
                    Ok(mut task) => loop {
                        match poll_fn(|cx| {
                            if stopping.load(Ordering::Acquire) {
                                return Poll::Ready(match task.close() {
                                    Ok(Some(event)) => {
                                        observe(&event);
                                        Err(Fault::Cancelled.into())
                                    }
                                    Ok(None) => Err(Fault::Cancelled.into()),
                                    Err(error) => Err(error),
                                });
                            }
                            task.poll(cx, None)
                        })
                        .await
                        {
                            Err(error) => break Err(error),
                            Ok(AddProgress::Finished(done)) => break Ok(done),
                            Ok(AddProgress::Native(event)) => observe(&event),
                            Ok(AddProgress::Admitted | AddProgress::WaitDeadline) => {}
                            Ok(AddProgress::Closed) => break Err(Fault::Closed.into()),
                        }
                    },
                }
            };
            // Close can leave real original terminal facts in the Client queue.
            // They are delivered before the owned result/client returns.
            if stopping.load(Ordering::Acquire) {
                while let Some(event) = client.next_event() {
                    observe(&event);
                }
            }
            Returned {
                client,
                finished: Finished { origin, result },
                observe,
            }
        }));
        // This observer moved into the owned future and is intentionally not
        // duplicated: exactly one source ever calls it at a time. It returns
        // with the same future when its original operation ends.
        Ok(())
    }
    /// Poll the actual helper even before an enclosing canonical clock wait;
    /// it registers/checks original native hard/STOP retirement targets itself.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Finished<'id, J>, Failure>> {
        let Some(running) = &mut self.running else {
            return Poll::Pending;
        };
        match running.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(returned) => {
                self.running = None;
                self.client = Some(returned.client);
                self.observe = Some(returned.observe);
                // A failed helper may physically close that source. Never recreate
                // or replay its original scan/STORE under another MQ here.
                if returned.finished.result.is_err() {
                    self.closed = true;
                }
                Poll::Ready(Ok(returned.finished))
            }
        }
    }
    /// Last actual terminal original returned during explicit physical stop.
    /// Consuming it is observation only, never renewal of a stopped authority.
    pub fn take_retired(&mut self) -> Option<Finished<'id, J>> {
        self.retired.take()
    }
    /// Physically retire without a clock/IO wait. The owned future's cancellation
    /// branch immediately closes its helper/client and preserves its original
    /// metadata/result. No native socket syscall or new operation starts here.
    pub fn close(&mut self) -> Vec<Failure> {
        self.closed = true;
        self.stopping.store(true, Ordering::Release);
        let mut errors = Vec::new();
        if let Some(running) = &mut self.running {
            let mut cx = Context::from_waker(Waker::noop());
            match running.as_mut().poll(&mut cx) {
                Poll::Ready(returned) => {
                    self.client = Some(returned.client);
                    self.observe = Some(returned.observe);
                    if let Err(error) = &returned.finished.result
                        && !matches!(error, ps::Error::Protocol(Fault::Cancelled))
                    {
                        errors.push(format!("HELLO-add original close: {error}").into());
                    }
                    self.retired = Some(returned.finished);
                }
                Poll::Pending => errors.push(
                    "HELLO-add immediate cancellation branch did not retire original source".into(),
                ),
            }
        }
        self.running = None;
        if let Some(client) = &mut self.client
            && let Err(error) = client.close()
        {
            errors.push(Box::new(error) as Failure);
        }
        errors
    }
}
