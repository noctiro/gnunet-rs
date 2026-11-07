use crate::{Error, Limits, Role, run::NativeEntropy};
use gnunet_paillier::{KeyPair, Keygen, Progress};
use gnunet_scalarproduct_paillier as p;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    mem::size_of,
    rc::Rc,
    task::{Context, Poll},
};
use tokio::time::Instant;

/// Explicit actual installed peer protocol. A source/peer error never switches
/// algorithms or retries the original intent with a different key/profile.
#[derive(Clone, Copy, Debug, Default)]
pub enum Profile {
    /// Existing ordinary default ECC, including its configured bounded DLOG.
    #[default]
    Ecc,
    /// Actual installed Paillier peer frames and full signed-MPI computation.
    Paillier(p::Limits),
}
impl Profile {
    /// Validate the selected complete resource/clock profile before native IO
    /// or entropy. The unchanged Server::new selects the exact ECC checks.
    pub fn validate(self, limits: Limits) -> Result<(), Error> {
        limits.validate_for(self)
    }
    /// Coherent selected defaults before explicit normal configuration
    /// overrides. Reservations allocate no maximum-size vectors/ciphertexts.
    pub fn default_host_limits(self) -> Result<Limits, Error> {
        let mut limits = Limits::default();
        if let Self::Paillier(policy) = self {
            limits.max_rows = policy.max_rows;
            limits.work_units = usize::from(policy.primitive.units_per_turn);
            limits.operation = std::time::Duration::from_micros(policy.lifetime_micros);
            limits.session_bytes = policy
                .max_retained_bytes
                .checked_add(limits.native_allowance()?)
                .ok_or(Fault::Overflow)?;
            limits.total_retained_bytes = limits
                .session_bytes
                .checked_mul(limits.clients)
                .and_then(|n| n.checked_add(256 * 1024))
                .ok_or(Fault::Overflow)?;
        }
        self.validate(limits)?;
        Ok(limits)
    }
    pub(crate) fn core_bytes(self, limits: Limits) -> usize {
        match self {
            Self::Ecc => limits.core.max_retained_bytes,
            Self::Paillier(core) => core.max_retained_bytes,
        }
    }
    pub(crate) fn input_budget(self, limits: Limits) -> Result<usize, Fault> {
        let overhead = match self {
            Self::Ecc => size_of::<gnunet_scalarproduct::Computation<'_>>(),
            Self::Paillier(_) => size_of::<p::Alice<'_>>()
                .max(size_of::<p::Bob<'_>>())
                .checked_add(limits.native_allowance()?)
                .ok_or(Fault::Overflow)?,
        };
        self.core_bytes(limits)
            .checked_sub(overhead)
            .ok_or(Fault::Capacity)
    }
    pub(crate) fn key_reservation(self, role: Role) -> Result<usize, Fault> {
        if matches!((self, role), (Self::Paillier(_), Role::Alice)) {
            // Keygen and live sessions never coexist: admission waits for ready.
            size_of::<KeyPair>()
                .checked_add(2 * size_of::<usize>())
                .ok_or(Fault::Overflow)
        } else {
            Ok(0)
        }
    }
}

pub(crate) struct KeyOwner {
    job: Vec<Keygen>,
    key: Option<Rc<KeyPair>>,
    entropy: NativeEntropy,
    units: u16,
    canonical_until: Option<u64>,
    native_until: Option<Instant>,
    required: bool,
    cancelled: bool,
}
impl KeyOwner {
    pub fn new(
        profile: Profile,
        role: Role,
        limits: Limits,
        clock: &dyn RuntimeClock,
    ) -> Result<Self, Error> {
        let mut owner = Self {
            job: Vec::new(),
            key: None,
            entropy: NativeEntropy::new(),
            units: 1,
            canonical_until: None,
            native_until: None,
            required: false,
            cancelled: false,
        };
        if let (Profile::Paillier(policy), Role::Alice) = (profile, role) {
            // This is a separate fixed startup target. No client intent has
            // started yet; each later query retains its own first admission.
            let duration =
                u64::try_from(limits.operation.as_micros()).map_err(|_| Fault::Overflow)?;
            let native = Instant::now()
                .checked_add(limits.operation)
                .ok_or(Fault::Overflow)?;
            let canonical = clock
                .sample()?
                .now
                .as_micros()
                .checked_add(duration)
                .ok_or(Fault::Overflow)?;
            if Instant::now() >= native {
                return Err(Fault::Deadline.into());
            }
            owner
                .job
                .try_reserve_exact(1)
                .map_err(|_| Fault::Capacity)?;
            if owner
                .job
                .capacity()
                .checked_mul(size_of::<Keygen>())
                .ok_or(Fault::Overflow)?
                > limits.total_retained_bytes
            {
                return Err(Fault::Capacity.into());
            }
            owner.job.push(
                Keygen::new(policy.primitive).map_err(|cause| Error::Paillier(cause.into()))?,
            );
            owner.units = u16::try_from(limits.work_units).map_err(|_| Fault::Overflow)?;
            owner.canonical_until = Some(canonical);
            owner.native_until = Some(native);
            owner.required = true;
        }
        Ok(owner)
    }
    pub fn ready(&self) -> bool {
        !self.cancelled && (!self.required || self.key.is_some())
    }
    pub fn pending(&self) -> bool {
        self.required && !self.cancelled && self.key.is_none()
    }
    pub fn key(&self) -> Option<Rc<KeyPair>> {
        self.key.clone()
    }
    pub fn retained_bytes(&self) -> Result<usize, Fault> {
        self.job
            .capacity()
            .checked_mul(size_of::<Keygen>())
            .and_then(|n| {
                n.checked_add(if self.key.is_some() {
                    size_of::<KeyPair>() + 2 * size_of::<usize>()
                } else {
                    0
                })
            })
            .ok_or(Fault::Overflow)
    }
    pub fn poll(
        &mut self,
        clock: &dyn RuntimeClock,
        cx: &mut Context<'_>,
    ) -> Poll<Result<bool, Error>> {
        if self.cancelled {
            return Poll::Ready(Err(Fault::Cancelled.into()));
        }
        if self.ready() {
            return Poll::Ready(Ok(false));
        }
        let result = (|| {
            if self.native_until.is_some_and(|at| Instant::now() >= at) {
                return Err(Fault::Deadline.into());
            }
            let now = clock.sample()?.now.as_micros();
            if self.canonical_until.is_some_and(|at| now >= at)
                || self.native_until.is_some_and(|at| Instant::now() >= at)
            {
                return Err(Fault::Deadline.into());
            }
            let job = self.job.first_mut().ok_or(Fault::NotReady)?;
            let progress = job.advance(&mut self.entropy, self.units);
            let progress = match progress {
                Ok(progress) => progress,
                Err(cause) => {
                    return Err(self
                        .entropy
                        .take_error()
                        .map_or_else(|| Error::Paillier(cause.into()), Error::Entropy));
                }
            };
            if progress == Progress::Ready {
                let pair = job
                    .take_result()
                    .map_err(|cause| Error::Paillier(cause.into()))?;
                self.key = Some(Rc::new(pair));
                self.job.clear();
                self.job = Vec::new();
                self.canonical_until = None;
                self.native_until = None;
            }
            Ok(true)
        })();
        if result.is_err() {
            self.cancel();
        }
        if matches!(result, Ok(true)) {
            cx.waker().wake_by_ref();
        }
        Poll::Ready(result)
    }
    pub fn cancel(&mut self) {
        for job in &mut self.job {
            job.cancel();
        }
        self.job.clear();
        self.job = Vec::new();
        self.key = None;
        self.cancelled = true;
        self.canonical_until = None;
        self.native_until = None;
    }
}
impl Drop for KeyOwner {
    fn drop(&mut self) {
        self.cancel();
    }
}
