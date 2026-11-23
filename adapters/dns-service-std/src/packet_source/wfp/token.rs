//! Unique service-side return ownership, without native I/O in Drop.
use gnunet_wfp_dns::RequestId;
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    task::{Context, Waker},
};

const HELD: u8 = 0;
const ABANDONED: u8 = 1;
const SUBMITTED: u8 = 2;
const RETIRED: u8 = 3;

pub(super) struct Owner {
    closed: AtomicBool,
    wake: Mutex<Option<Waker>>,
}

impl Owner {
    pub fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            wake: Mutex::new(None),
        }
    }

    fn wake_slot(&self) -> std::sync::MutexGuard<'_, Option<Waker>> {
        // No user code runs while this mutex is held. A poisoned ownership
        // record cannot safely be recovered as permission to inject or discard.
        match self.wake.lock() {
            Ok(slot) => slot,
            Err(_) => std::process::abort(),
        }
    }

    pub fn register(&self, cx: &Context<'_>) {
        let fresh = cx.waker().clone();
        let old = self.wake_slot().replace(fresh);
        drop(old);
    }

    fn notify(&self) {
        let wake = self.wake_slot().take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify();
    }
}

pub(super) struct Token {
    pub request: RequestId,
    pub index: usize,
    owner: Arc<Owner>,
    phase: AtomicU8,
}

impl Token {
    pub fn new(request: RequestId, index: usize, owner: Arc<Owner>) -> Arc<Self> {
        Arc::new(Self {
            request,
            index,
            owner,
            phase: AtomicU8::new(HELD),
        })
    }

    pub fn belongs_to(&self, owner: &Arc<Owner>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }
    pub fn held(&self) -> bool {
        self.phase.load(Ordering::Acquire) == HELD
    }
    pub fn abandoned(&self) -> bool {
        self.phase.load(Ordering::Acquire) == ABANDONED
    }
    pub fn submitted(&self) {
        self.phase.store(SUBMITTED, Ordering::Release);
    }
    pub fn retire(&self) {
        self.phase.store(RETIRED, Ordering::Release);
    }
}

/// Unique original device request paired with its owning source generation.
/// Dropping an unsubmitted endpoint schedules one bounded discard for that
/// source; it performs no native calls and creates no replacement authority.
pub(crate) struct Endpoint {
    pub(super) token: Arc<Token>,
}

impl Endpoint {
    pub(super) fn new(token: Arc<Token>) -> Self {
        Self { token }
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WfpReplyEndpoint")
            .field("request", &self.token.request)
            .finish_non_exhaustive()
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if !self.token.owner.closed.load(Ordering::Acquire)
            && self
                .token
                .phase
                .compare_exchange(HELD, ABANDONED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.token.owner.notify();
        }
    }
}
