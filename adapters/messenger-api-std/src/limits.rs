use gnunet_types::Error as Fault;
use std::time::Duration;
/// Finite high-level metadata/work bounds, together with the actual independent
/// native-frame and domain-state allocation budgets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual native MQ limits and explicit original service producer profile.
    pub native: gnunet_messenger_client_host::Limits,
    /// Retained room/message/member/history/epoch state capacities.
    pub core: gnunet_messenger_core::Limits,
    /// Original high-level jobs including whole-written jobs awaiting real input.
    pub operations: usize,
    /// Maximum owned opaque local signing identities, including rotations.
    pub identities: usize,
    /// Default lifetime of each original internal initialization/key job.
    pub operation_lifetime: Duration,
    /// Metadata/scratch/pending-original allocation budget, outside core/native.
    pub bytes: usize,
    /// Maximum room/provider phases per progress turn. Each domain phase also
    /// obeys core.work_per_turn; no unbounded callback or room scan occurs.
    pub work_per_poll: usize,
    /// Whether each actual joined room drives official epoch key distribution.
    pub automatic_epochs: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            native: gnunet_messenger_client_host::Limits::default(),
            core: gnunet_messenger_core::Limits::default(),
            operations: 256,
            identities: 8,
            operation_lifetime: Duration::from_secs(10),
            bytes: 4 * 1024 * 1024,
            work_per_poll: 4,
            automatic_epochs: true,
        }
    }
}
impl Limits {
    pub(crate) fn validate<const N: usize>(self) -> Result<(), Fault> {
        self.native.profile.validate()?;
        self.core.validate().map_err(|e| match e {
            gnunet_messenger_core::Error::Protocol(f) => f,
            _ => Fault::InvalidInput,
        })?;
        if N < 384
            || N > 65524
            || self.operations == 0
            || self.identities == 0
            || self.work_per_poll == 0
            || self.bytes == 0
            || self.operation_lifetime.as_micros() == 0
            || self.operation_lifetime.as_micros() > u128::from(u64::MAX)
            || std::time::Instant::now()
                .checked_add(self.operation_lifetime)
                .is_none()
        {
            return Err(Fault::InvalidInput);
        }
        let scratch = N.checked_mul(2).ok_or(Fault::Overflow)?;
        if scratch > self.bytes {
            return Err(Fault::Capacity);
        }
        Ok(())
    }
}
