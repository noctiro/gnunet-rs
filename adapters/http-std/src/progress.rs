use crate::Job;
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
/// Separate factual observations for one original HTTP request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// Immutable request retained in this bounded owner, not a Hyper/service ACK.
    pub queued: bool,
    /// The original ready sender's dispatch API was invoked; not a write receipt.
    pub dispatch_called: bool,
    /// A nonempty application write was actually polled. Errors/Pending may leave
    /// opaque TLS buffering state; conservatively possible exposure, never success.
    pub write_attempted: bool,
    /// Exact bytes accepted by the outer application stream's AsyncWrite API.
    /// With TLS these are plaintext accepted by TLS, not bytes accepted by TCP.
    pub plaintext_accepted: usize,
    /// Actual socket bytes accepted after request dispatch, possibly ciphertext
    /// or final TLS/proxy framing. They are not an exact HTTP plaintext prefix.
    pub socket_after_dispatch: usize,
    /// Actual outer-stream flush returned Ok; no whole-request or remote ACK.
    pub flush_observed: bool,
    /// Actual HTTP response headers received, possibly an explicit safe redirect.
    pub response_headers: bool,
    /// Actual bounded original final response reached entity EOF/HEAD completion.
    pub response_complete: bool,
}
impl Snapshot {
    /// Unknown application outcome can exist without a completed response or
    /// positive TCP count: TLS accepted/buffered plaintext is a separate fact.
    pub fn may_have_exposed(self) -> bool {
        self.write_attempted || self.plaintext_accepted != 0
    }
}
#[derive(Default)]
pub(crate) struct State {
    pub queued: AtomicBool,
    pub dispatch: AtomicBool,
    pub attempted: AtomicBool,
    pub plaintext: AtomicUsize,
    pub socket: AtomicUsize,
    pub flushed: AtomicBool,
    pub headers: AtomicBool,
    pub complete: AtomicBool,
}
/// Borrowable retained progress for the same original Job across cancellation.
/// Its private constructor prevents caller-created success/response receipts.
#[derive(Clone)]
pub struct Progress {
    job: Job,
    pub(crate) state: Arc<State>,
}
impl Progress {
    pub(crate) fn new(job: Job) -> Self {
        Self {
            job,
            state: Arc::new(State::default()),
        }
    }
    /// Original immutable request token; a new owner never retags old progress.
    pub fn job(&self) -> &Job {
        &self.job
    }
    /// Actual independent original IO stages, atomically sampled without IO.
    pub fn snapshot(&self) -> Snapshot {
        let s = &self.state;
        Snapshot {
            queued: s.queued.load(Ordering::Acquire),
            dispatch_called: s.dispatch.load(Ordering::Acquire),
            write_attempted: s.attempted.load(Ordering::Acquire),
            plaintext_accepted: s.plaintext.load(Ordering::Acquire),
            socket_after_dispatch: s.socket.load(Ordering::Acquire),
            flush_observed: s.flushed.load(Ordering::Acquire),
            response_headers: s.headers.load(Ordering::Acquire),
            response_complete: s.complete.load(Ordering::Acquire),
        }
    }
}
impl fmt::Debug for Progress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProgress")
            .field("job", &self.job)
            .field("snapshot", &self.snapshot())
            .finish()
    }
}
