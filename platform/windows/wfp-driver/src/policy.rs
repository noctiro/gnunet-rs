//! Original driver-owned receive guards and capture lifecycle filters.
//!
//! Deployment must provision the fixed static callout metadata first.
//! This module neither creates nor adopts its ownership. Catalog observations
//! cannot pin a kernel registration or establish the metadata's session lifetime.

mod capture;
mod catalog;
mod engine;
mod error;

pub use error::{Cleanup, Datagram, Error, NativeFailure, Problem, Retirement};

use crate::callbacks;
use core::{fmt, num::NonZeroU64, pin::Pin};
use engine::Engine;

/// Bounded local-engine transaction acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum BFE transaction wait, from 1 through 30,000 milliseconds.
    pub transaction_wait_ms: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            transaction_wait_ms: 2_000,
        }
    }
}

enum State {
    Empty,
    Owned(Owned),
    Retired(Retirement),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Transaction {
    Idle,
    Setup,
    Removal,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Scope {
    Capture,
    All,
}

struct Owned {
    engine: Engine,
    transaction: Transaction,
    provider: bool,
    sublayer: bool,
    guards: [Option<NonZeroU64>; 2],
    capture: [Option<NonZeroU64>; 6],
    installed: bool,
    session_aborted: Option<NativeFailure>,
    uncertain_close: Option<Retirement>,
}

/// Exclusive custody of one original dynamic guard-engine session.
///
/// Store this owner through the complete native driver-state lifetime. There is
/// deliberately no `Drop`: removing receive guards requires native drain first.
/// A failed close retains the original engine and forbids automatic retries.
#[must_use = "retain the owner and explicitly retire it only after native drain"]
pub struct Policy {
    state: State,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Policy")
            .field("installed", &self.is_installed())
            .field("has_original_engine", &self.has_original_engine())
            .field("close_uncertain", &self.close_uncertain())
            .field("last_retirement", &self.last_retirement())
            .finish()
    }
}

impl Policy {
    /// Creates an empty owner without opening an engine or changing policy.
    pub const fn new() -> Self {
        Self {
            state: State::Empty,
        }
    }

    /// Install the original receive guards and capture lifecycle filters atomically.
    ///
    /// The separately provisioned metadata must identify this
    /// driver's registered native callouts. Registration IDs are observations,
    /// not registration ownership or a service-readiness proof. A collision with
    /// existing guard objects fails; no object is adopted or replaced.
    ///
    /// On failure, cleanup uses this original engine. Any failed-close custody
    /// remains in `self`, separately from the original error returned to callers.
    ///
    /// # Errors
    /// Rejects invalid limits, reuse, incompatible callout metadata, guard-key
    /// collisions, and original kernel FWPM failures. Inspect
    /// [`Self::last_retirement`] for cleanup observations.
    ///
    /// # Safety
    /// Execute at PASSIVE_LEVEL without an arena/spin lock held. Keep the actual
    /// FWPS registrations and full native state alive. Admission must be closed
    /// and there must be no outstanding native injections: setup failure may
    /// remove guards and close the engine before returning.
    pub unsafe fn install(
        &mut self,
        limits: Limits,
        callback: Pin<&callbacks::State>,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::Empty) {
            return Err(Error::AlreadyStarted);
        }
        if !(1..=30_000).contains(&limits.transaction_wait_ms) {
            return Err(Error::InvalidLimits);
        }
        let engine = Engine::open(limits.transaction_wait_ms)?;
        let mut owned = Owned::new(engine);
        let result = owned.install(callback);
        if let Err(Error::Native(error)) = result
            && error.session_aborted()
        {
            owned.record_session_abort(error);
        }
        self.state = State::Owned(owned);
        if result.is_err() {
            callback.stop_capture();
            // SAFETY: the install contract excludes active native admissions and
            // injections, including during startup-failure cleanup.
            let _ = unsafe { self.retire_after_drain() };
        }
        result
    }

    /// Whether guard installation committed and retirement has not begun.
    /// This reports this owner's catalog changes, never native readiness/drain.
    pub fn is_installed(&self) -> bool {
        matches!(&self.state, State::Owned(owned) if owned.installed)
    }

    /// Whether custody of the original engine still resides in this owner.
    pub fn has_original_engine(&self) -> bool {
        matches!(self.state, State::Owned(_))
    }

    /// Whether one failed original close makes further automatic calls unsafe.
    pub fn close_uncertain(&self) -> bool {
        matches!(&self.state, State::Owned(owned) if owned.uncertain_close.is_some())
    }

    /// Original cleanup receipt, retained even after successful engine close.
    pub fn last_retirement(&self) -> Option<Retirement> {
        match &self.state {
            State::Owned(owned) => owned.uncertain_close,
            State::Retired(receipt) => Some(*receipt),
            State::Empty => None,
        }
    }

    /// Whether the original engine retains any discovery, capture or endpoint closure filter.
    /// An unsettled transaction never proves filter retirement.
    pub fn capture_retired(&self) -> bool {
        let State::Owned(owned) = &self.state else {
            return true;
        };
        owned.transaction == Transaction::Idle && owned.capture.iter().all(Option::is_none)
    }

    /// Remove the original discovery, capture and endpoint closure filters in
    /// one transaction after revoking all reply authority.
    /// Keep the independent inbound guards, provider and engine live.
    ///
    /// # Safety
    /// Call at PASSIVE_LEVEL after revoking local capture admission. Preserve
    /// the original callout registrations, handles and callback storage.
    pub unsafe fn retire_capture(&mut self) -> Retirement {
        match &mut self.state {
            State::Owned(owned) => owned.retire(Scope::Capture),
            State::Retired(receipt) => *receipt,
            State::Empty => Retirement::default(),
        }
    }

    /// Remove owned filters transactionally and close the original engine.
    ///
    /// Every native cleanup observation is preserved. A failed close retains
    /// custody and returns that same receipt on subsequent calls, without querying
    /// or retrying a numerical handle that might have been reused. The full
    /// native driver state must remain alive until its lifecycle is independently
    /// resolved; a failed receipt is not permission to unload registrations.
    ///
    /// # Safety
    /// Execute at PASSIVE_LEVEL without an arena/spin lock held. Admission must
    /// be closed and all original native injections must actually have drained.
    /// Keep the actual FWPS registrations and complete native state alive through
    /// these calls; closing a management engine is not WFP callback drain proof.
    pub unsafe fn retire_after_drain(&mut self) -> Retirement {
        let receipt = match &mut self.state {
            State::Owned(owned) => owned.retire(Scope::All),
            State::Retired(receipt) => return *receipt,
            State::Empty => return Retirement::default(),
        };
        if receipt.engine_close == Cleanup::Succeeded {
            self.state = State::Retired(receipt);
        }
        receipt
    }
}

impl Owned {
    fn new(engine: Engine) -> Self {
        Self {
            engine,
            transaction: Transaction::Idle,
            provider: false,
            sublayer: false,
            guards: [None; 2],
            capture: [None; 6],
            installed: false,
            session_aborted: None,
            uncertain_close: None,
        }
    }

    fn install(&mut self, callback: Pin<&callbacks::State>) -> Result<(), Error> {
        self.engine.begin()?;
        self.transaction = Transaction::Setup;
        let guards = catalog::guards();
        for guard in &guards {
            self.engine
                .observe_callout(guard.family, &guard.callout, guard.layer)?;
        }
        self.engine.add_provider()?;
        self.provider = true;
        self.engine.add_sublayer()?;
        self.sublayer = true;
        for (index, guard) in guards.iter().enumerate() {
            let id = self.engine.add_guard(guard)?;
            self.guards[index] = Some(id);
            self.engine.confirm_guard(guard, id)?;
        }
        for (index, rule) in capture::rules().iter().enumerate() {
            self.capture[index] = Some(self.engine.add_capture(rule)?);
        }
        let [Some(a), Some(b)] = self.guards else {
            return Err(Error::Incomplete);
        };
        let [Some(c), Some(d), Some(e), Some(f), Some(g), Some(h)] = self.capture else {
            return Err(Error::Incomplete);
        };
        // SAFETY: these are original, shape-checked additions from this
        // transaction. Publishing now lets DELETE revoke a filter even if the
        // callback is delivered during the native commit.
        unsafe { callback.stage_policy([a, b], [c, d, e, f, g, h]) }.map_err(Error::Routing)?;
        self.engine.commit()?;
        self.transaction = Transaction::Idle;
        self.installed = true;
        Ok(())
    }

    fn clear_effects(&mut self, scope: Scope) {
        if scope == Scope::All {
            self.provider = false;
            self.sublayer = false;
            self.guards = [None; 2];
        }
        self.capture = [None; 6];
        self.installed = false;
    }

    fn mark_unattempted(&self, receipt: &mut Retirement, scope: Scope) {
        for (output, id) in
            receipt
                .capture
                .iter_mut()
                .zip(self.capture)
                .chain(receipt.guards.iter_mut().zip(if scope == Scope::All {
                    self.guards
                } else {
                    [None; 2]
                }))
        {
            if id.is_some() {
                *output = Cleanup::NotAttempted;
            }
        }
        if scope == Scope::All && self.sublayer {
            receipt.sublayer = Cleanup::NotAttempted;
        }
        if scope == Scope::All && self.provider {
            receipt.provider = Cleanup::NotAttempted;
        }
    }

    fn remove_effects(&mut self, receipt: &mut Retirement, scope: Scope) {
        receipt.removal_begin = Cleanup::observe(self.engine.begin());
        if self.observe_aborted(receipt.removal_begin, receipt) {
            return;
        }
        if receipt.removal_begin != Cleanup::Succeeded {
            self.mark_unattempted(receipt, scope);
            receipt.removal_commit = Cleanup::NotAttempted;
            return;
        }
        self.transaction = Transaction::Removal;
        let mut aborted = None;
        for (index, (output, id)) in receipt
            .capture
            .iter_mut()
            .zip(self.capture)
            .chain(receipt.guards.iter_mut().zip(if scope == Scope::All {
                self.guards
            } else {
                [None; 2]
            }))
            .enumerate()
        {
            if let Some(id) = id {
                *output = Cleanup::observe(self.engine.delete_filter(id));
                if let Some(error) = output.session_aborted() {
                    aborted = Some(error);
                    break;
                }
                if output.absent(
                    "FwpmFilterDeleteById0",
                    crate::sdk::GNUNET_WFP_STATUS_FWP_FILTER_NOT_FOUND,
                ) {
                    // A missing object was not mutated by this transaction, so
                    // abort cannot restore it. Retain the raw native refusal.
                    if index < self.capture.len() {
                        self.capture[index] = None;
                    } else {
                        self.guards[index - self.capture.len()] = None;
                    }
                }
            }
        }
        if let Some(error) = aborted {
            self.record_session_abort(error);
            receipt.session_aborted = self.session_aborted;
            return;
        }
        if scope == Scope::All && self.sublayer {
            receipt.sublayer = Cleanup::observe(self.engine.delete_sublayer());
            if self.observe_aborted(receipt.sublayer, receipt) {
                return;
            }
            if receipt.sublayer.absent(
                "FwpmSubLayerDeleteByKey0",
                crate::sdk::GNUNET_WFP_STATUS_FWP_SUBLAYER_NOT_FOUND,
            ) {
                self.sublayer = false;
            }
        }
        if scope == Scope::All && self.provider {
            receipt.provider = Cleanup::observe(self.engine.delete_provider());
            if self.observe_aborted(receipt.provider, receipt) {
                return;
            }
            if receipt.provider.absent(
                "FwpmProviderDeleteByKey0",
                crate::sdk::GNUNET_WFP_STATUS_FWP_PROVIDER_NOT_FOUND,
            ) {
                self.provider = false;
            }
        }
        if receipt.guards.iter().chain(&receipt.capture).any(|entry| {
            entry.blocks_removal(
                "FwpmFilterDeleteById0",
                crate::sdk::GNUNET_WFP_STATUS_FWP_FILTER_NOT_FOUND,
            )
        }) || receipt.sublayer.blocks_removal(
            "FwpmSubLayerDeleteByKey0",
            crate::sdk::GNUNET_WFP_STATUS_FWP_SUBLAYER_NOT_FOUND,
        ) || receipt.provider.blocks_removal(
            "FwpmProviderDeleteByKey0",
            crate::sdk::GNUNET_WFP_STATUS_FWP_PROVIDER_NOT_FOUND,
        ) {
            receipt.removal_commit = Cleanup::NotAttempted;
        } else {
            receipt.removal_commit = Cleanup::observe(self.engine.commit());
            if self.observe_aborted(receipt.removal_commit, receipt) {
                return;
            }
            if receipt.removal_commit == Cleanup::Succeeded {
                self.transaction = Transaction::Idle;
                self.clear_effects(scope);
                return;
            }
        }
        receipt.removal_abort = Cleanup::observe(self.engine.abort());
        if self.observe_aborted(receipt.removal_abort, receipt) {
            return;
        }
        if receipt.removal_abort == Cleanup::Succeeded {
            self.transaction = Transaction::Idle;
        }
    }

    fn retire(&mut self, scope: Scope) -> Retirement {
        if let Some(receipt) = self.uncertain_close {
            return receipt;
        }
        self.installed = false;
        let mut receipt = Retirement {
            session_aborted: self.session_aborted,
            ..Retirement::default()
        };
        if self.transaction == Transaction::Setup {
            receipt.setup_abort = Cleanup::observe(self.engine.abort());
            if !self.observe_aborted(receipt.setup_abort, &mut receipt)
                && receipt.setup_abort == Cleanup::Succeeded
            {
                self.transaction = Transaction::Idle;
                self.clear_effects(Scope::All);
            }
        } else if self.transaction == Transaction::Removal {
            receipt.removal_abort = Cleanup::observe(self.engine.abort());
            if !self.observe_aborted(receipt.removal_abort, &mut receipt)
                && receipt.removal_abort == Cleanup::Succeeded
            {
                self.transaction = Transaction::Idle;
                // Aborting removal leaves the previously committed policy in place.
            }
        }
        if self.transaction != Transaction::Idle {
            receipt.removal_begin = Cleanup::NotAttempted;
            receipt.removal_commit = Cleanup::NotAttempted;
            self.mark_unattempted(&mut receipt, scope);
        } else if self.capture.iter().any(Option::is_some)
            || (scope == Scope::All
                && (self.provider || self.sublayer || self.guards.iter().any(Option::is_some)))
        {
            self.remove_effects(&mut receipt, scope);
        }
        if scope == Scope::All {
            receipt.engine_close = Cleanup::observe(self.engine.close());
            self.observe_aborted(receipt.engine_close, &mut receipt);
            if receipt.engine_close.failed() {
                self.uncertain_close = Some(receipt);
            }
        }
        receipt
    }

    fn observe_aborted(&mut self, observation: Cleanup, receipt: &mut Retirement) -> bool {
        let Some(error) = observation.session_aborted() else {
            return false;
        };
        self.record_session_abort(error);
        receipt.session_aborted = self.session_aborted;
        true
    }

    fn record_session_abort(&mut self, error: NativeFailure) {
        self.session_aborted.get_or_insert(error);
        // WFP destroys dynamic objects when their original session terminates.
        // SESSION_ABORTED still requires FwpmEngineClose0 for client-side state;
        // neither this bookkeeping nor BFE RUNNING releases that original handle.
        self.transaction = Transaction::Idle;
        self.clear_effects(Scope::All);
    }
}
