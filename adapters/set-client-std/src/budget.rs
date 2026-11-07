//! Immutable original source/operation deadlines.
use crate::Error;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    pin::Pin,
    task::Context,
    time::{Duration, Instant},
};
use tokio::time::Sleep;
/// Which exact original bound actually refused work. Labels are diagnostics,
/// not source, request or replacement authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineScope {
    /// A new budget exhausted its native interval before a canonical target existed.
    BudgetCreation,
    /// A caller-supplied bound checked without a more specific owner.
    Budget,
    /// Original physical Set/Listener lifetime.
    Overall,
    /// Original attach and initializer-write interval.
    Initial,
    /// Original incomplete response, measured from its first bytes.
    PartialInput,
    /// Original queued write and its exact immutable correlation.
    Write(DeadlineWrite),
    /// Original reconciliation, not a peer completion.
    Operation {
        /// Original local operation serial on this same Set.
        serial: u64,
        /// Original public correlation, never a replacement owner.
        request_id: u32,
    },
    /// Original enumeration or its already captured cleanup target.
    Iteration {
        /// Original local enumeration serial.
        serial: u64,
        /// Original public enumeration generation.
        generation: u16,
        /// Whether this is the independently captured cancellation cleanup bound.
        cleanup: bool,
    },
    /// Original lazy-copy query.
    Copy {
        /// Original local lazy-copy query serial.
        serial: u64,
    },
}
/// Diagnostic labels for original queued bytes. None grants the corresponding
/// operation, mutation, iteration, copy or listener authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineWrite {
    /// Original Add/Remove continuation.
    Mutation {
        /// Original local Add/Remove serial.
        serial: u64,
    },
    /// Original Evaluate/Accept correlation.
    Operation {
        /// Original public Evaluate/Accept correlation.
        request_id: u32,
    },
    /// Original Cancel correlation.
    Cancel {
        /// Original public operation correlation.
        request_id: u32,
    },
    /// Original Iterate continuation.
    Iterate {
        /// Original local enumeration serial.
        serial: u64,
    },
    /// Original IterAck continuation and its unchanged public flag.
    IterAck {
        /// Original local enumeration serial.
        serial: u64,
        /// Original unchanged public continuation flag.
        send_more: bool,
    },
    /// Original CopyLazyPrepare continuation.
    Copy {
        /// Original local lazy-copy query serial.
        serial: u64,
    },
    /// Original listener rejection correlation.
    Reject {
        /// Original incoming correlation on this listener.
        accept_id: u32,
    },
}
/// Fixed inline facts captured by the actual refusing predicate. A native-only
/// guard never samples the canonical Clock to populate this record.
#[derive(Clone, Copy, Debug)]
pub struct DeadlineContext {
    /// Actual refusing owner/phase, rather than an inference from an error code.
    pub scope: DeadlineScope,
    /// Unchanged original canonical target. None only during BudgetCreation,
    /// before that target existed; no fabricated canonical value is supplied.
    pub expires: Option<u64>,
    /// Unchanged original native target.
    pub hard: Instant,
    /// Native instant observed at this actual refusing check.
    pub observed_native: Instant,
    /// Sample already obtained by this check; None for clock-free native fences.
    pub observed_canonical: Option<u64>,
}
impl DeadlineContext {
    pub(crate) const fn at(
        scope: DeadlineScope,
        original: Bounds,
        observed_native: Instant,
        observed_canonical: Option<u64>,
    ) -> Self {
        Self {
            scope,
            expires: Some(original.expires),
            hard: original.hard,
            observed_native,
            observed_canonical,
        }
    }
}
/// Original caller budget, without source or operation authority.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Original canonical target in microseconds.
    pub expires: u64,
    /// Original native target, never renewed by reconnect or partial IO.
    pub hard: Instant,
}
impl Bounds {
    /// Capture native first, then the actual shared canonical sample.
    pub fn new(clock: &dyn RuntimeClock, life: Duration) -> Result<Self, Error> {
        let start = Instant::now();
        if life.is_zero() || life.as_micros() >= u128::from(u64::MAX) {
            return Err(Fault::InvalidInput.into());
        }
        let hard = start.checked_add(life).ok_or(Fault::Overflow)?;
        let now = clock.sample().map_err(Error::clock)?.now.as_micros();
        let observed_native = Instant::now();
        if observed_native >= hard {
            return Err(Error::deadline(DeadlineContext {
                scope: DeadlineScope::BudgetCreation,
                expires: None,
                hard,
                observed_native,
                observed_canonical: Some(now),
            }));
        }
        let expires = now
            .checked_add(u64::try_from(life.as_micros()).map_err(|_| Fault::Overflow)?)
            .filter(|x| *x != u64::MAX)
            .ok_or(Fault::Overflow)?;
        Ok(Self { expires, hard })
    }
    pub(crate) fn phase(
        clock: &dyn RuntimeClock,
        life: Duration,
        overall: Bounds,
    ) -> Result<Self, Error> {
        let mut target = Self::new(clock, life)?;
        target.hard = target.hard.min(overall.hard);
        target.expires = target.expires.min(overall.expires);
        Ok(target)
    }
    pub(crate) fn check(self, clock: &dyn RuntimeClock) -> Result<(), Error> {
        self.check_scoped(clock, DeadlineScope::Budget)
    }
    pub(crate) fn check_scoped(
        self,
        clock: &dyn RuntimeClock,
        scope: DeadlineScope,
    ) -> Result<(), Error> {
        let native = Instant::now();
        if native >= self.hard {
            return Err(Error::deadline(DeadlineContext::at(
                scope, self, native, None,
            )));
        }
        let now = clock.sample().map_err(Error::clock)?.now.as_micros();
        let native = Instant::now();
        if native >= self.hard || now >= self.expires {
            return Err(Error::deadline(DeadlineContext::at(
                scope,
                self,
                native,
                Some(now),
            )));
        }
        Ok(())
    }
}
/// One live owner's reusable earliest-native-target waiter. Receipts retain
/// only their immutable Bounds; no pending future moves into terminal facts.
#[derive(Default)]
pub(crate) struct NativeAlarm {
    alarm: Option<Pin<Box<Sleep>>>,
}
impl NativeAlarm {
    pub fn poll(&mut self, cx: &mut Context<'_>, target: Option<Instant>) -> bool {
        let Some(target) = target else {
            self.clear();
            return false;
        };
        if Instant::now() >= target {
            self.clear();
            return true;
        }
        let target = target.into();
        let alarm = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
        if alarm.deadline() != target {
            // A removed/settled earliest operation may move the next target
            // later; a newly admitted one may move it earlier. Neither renews
            // any original Bounds, and reset clears old ready timer state.
            alarm.as_mut().reset(target);
        }
        alarm.as_mut().poll(cx).is_ready()
    }
    pub fn clear(&mut self) {
        self.alarm = None;
    }
}
