//! Weak waiters and one serialized admission boundary for the original worker.
use super::{Error, Job, Output, Task};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, TryAcquireError, mpsc, oneshot};

struct Queued {
    job: Job,
    slot: OwnedSemaphorePermit,
}
pub(super) struct Receiver(mpsc::UnboundedReceiver<Queued>);
impl Receiver {
    pub(super) fn blocking_recv(&mut self) -> Option<Job> {
        self.0.blocking_recv().map(Self::release)
    }
    fn release(queued: Queued) -> Job {
        // Release queue capacity before executing the blocking operation.
        drop(queued.slot);
        queued.job
    }
    #[cfg(test)]
    fn try_recv(&mut self) -> Result<Job, mpsc::error::TryRecvError> {
        self.0.try_recv().map(Self::release)
    }
}

pub(super) struct Queue {
    sender: Mutex<Option<mpsc::UnboundedSender<Queued>>>,
    slots: Arc<Semaphore>,
}
pub(super) enum Refusal {
    Full,
    Closed,
}
impl Queue {
    pub(super) fn new(capacity: usize) -> (Arc<Self>, Receiver) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                sender: Mutex::new(Some(sender)),
                slots: Arc::new(Semaphore::new(capacity)),
            }),
            Receiver(receiver),
        )
    }
    pub(super) fn try_send(&self, job: Job) -> Result<(), Refusal> {
        let slot = match Arc::clone(&self.slots).try_acquire_owned() {
            Ok(slot) => slot,
            Err(TryAcquireError::Closed) => {
                return Err(Refusal::Closed);
            }
            Err(TryAcquireError::NoPermits) => {
                return Err(Refusal::Full);
            }
        };
        self.send(job, slot)
    }
    fn send(&self, job: Job, slot: OwnedSemaphorePermit) -> Result<(), Refusal> {
        let Ok(sender) = self.sender.lock() else {
            return Err(Refusal::Closed);
        };
        match sender.as_ref() {
            // The only send path requires one permit owned by this queue.
            // Each queued envelope retains that slot until its actual dequeue.
            Some(sender) => sender
                .send(Queued { job, slot })
                .map_err(|_| Refusal::Closed),
            None => Err(Refusal::Closed),
        }
    }
    pub(super) fn close(&self) {
        // Admission and close share one short, nonblocking critical section.
        // A concurrently upgraded weak port cannot submit after this boundary.
        if let Ok(mut sender) = self.sender.lock() {
            *sender = None;
        }
        self.slots.close();
    }
}

type Permit = Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send>>;

pub(in super::super) struct Pending {
    queue: Weak<Queue>,
    permit: Option<Permit>,
    job: Option<Job>,
    result: oneshot::Receiver<Result<Output, Arc<Error>>>,
}
impl Pending {
    pub(super) fn new(queue: &Arc<Queue>, task: Task) -> Self {
        let (result, receiver) = oneshot::channel();
        Self {
            queue: Arc::downgrade(queue),
            // A capacity waiter retains only the semaphore, never a sender.
            // Tokio's FIFO permits keep readonly try-send ports from starving
            // already waiting registration, removal or enumeration requests.
            permit: Some(Box::pin(Arc::clone(&queue.slots).acquire_owned())),
            job: Some(Job { task, result }),
            result: receiver,
        }
    }
    /// Only a successful queue send admits work to the original index thread.
    pub(in super::super) fn admitted(&self) -> bool {
        self.job.is_none()
    }
    pub(in super::super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Output, Arc<Error>>> {
        if let Some(permit) = &mut self.permit {
            let slot = match permit.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    self.permit = None;
                    self.job = None;
                    return Poll::Ready(Err(Arc::new(Error::WorkerGone)));
                }
                Poll::Ready(Ok(slot)) => slot,
            };
            self.permit = None;
            let Some(queue) = self.queue.upgrade() else {
                self.job = None;
                return Poll::Ready(Err(Arc::new(Error::WorkerGone)));
            };
            let Some(job) = self.job.take() else {
                return Poll::Ready(Err(Arc::new(Error::WorkerGone)));
            };
            if queue.send(job, slot).is_err() {
                return Poll::Ready(Err(Arc::new(Error::WorkerGone)));
            }
        }
        Pin::new(&mut self.result)
            .poll(cx)
            .map(|result| result.unwrap_or_else(|_| Err(Arc::new(Error::WorkerGone))))
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Queue tests propagate receive errors and assert admission, wake and retirement contracts"
)]
mod tests {
    use super::*;
    use std::task::{Wake, Waker};

    #[derive(Default)]
    struct Wakes(std::sync::atomic::AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[test]
    fn close_wakes_unissued_work_and_preserves_original_admitted_receipt()
    -> Result<(), mpsc::error::TryRecvError> {
        let (queue, mut receiver) = Queue::new(1);
        let mut admitted = Pending::new(&queue, Task::CollectGarbage);
        let mut waiting = Pending::new(&queue, Task::Next(None));
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        assert!(admitted.poll(&mut cx).is_pending());
        assert!(waiting.poll(&mut cx).is_pending());
        queue.close();
        assert!(wakes.0.load(std::sync::atomic::Ordering::Relaxed) > 0);
        drop(queue);
        assert!(matches!(
            waiting.poll(&mut cx),
            Poll::Ready(Err(error)) if matches!(error.as_ref(), Error::WorkerGone)
        ));
        let job = receiver.try_recv()?;
        assert!(job.result.send(Ok(Output::Maintained)).is_ok());
        assert!(matches!(
            admitted.poll(&mut cx),
            Poll::Ready(Ok(Output::Maintained))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        Ok(())
    }

    #[test]
    fn dequeued_capacity_wakes_the_same_waiter_without_replaying_a_job()
    -> Result<(), mpsc::error::TryRecvError> {
        let (queue, mut receiver) = Queue::new(1);
        let mut first = Pending::new(&queue, Task::CollectGarbage);
        let mut second = Pending::new(&queue, Task::Next(None));
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        assert!(first.poll(&mut cx).is_pending());
        assert!(second.poll(&mut cx).is_pending());
        let original = receiver.try_recv()?;
        assert!(wakes.0.load(std::sync::atomic::Ordering::Relaxed) > 0);
        let (result, _receiver) = oneshot::channel();
        assert!(
            matches!(
                queue.try_send(Job {
                    task: Task::CollectGarbage,
                    result
                }),
                Err(Refusal::Full)
            ),
            "a later readonly request stole the original waiter's capacity"
        );
        assert!(second.poll(&mut cx).is_pending());
        let next = receiver.try_recv()?;
        assert!(matches!(next.task, Task::Next(None)));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(original.result.send(Ok(Output::Maintained)).is_ok());
        assert!(next.result.send(Err(Arc::new(Error::WorkerGone))).is_ok());
        assert!(matches!(
            first.poll(&mut cx),
            Poll::Ready(Ok(Output::Maintained))
        ));
        assert!(matches!(second.poll(&mut cx), Poll::Ready(Err(_))));
        Ok(())
    }
}
