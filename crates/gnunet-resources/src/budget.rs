//! Independent physical resource partitions and noncloneable reservations.
use gnunet_types::{Bytes, Error, MessageSlots, Rejected};

/// Independent resource classes; DATA cannot borrow the control reserve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Partition {
    /// Immutable reliable source retention.
    ReliableRetention,
    /// Temporary records awaiting seal or device progress.
    RecordProgress,
    /// Receive and preauthentication reassembly.
    Receive,
    /// Guaranteed bounded ACK, cancellation and shutdown progress.
    ControlReserve,
    /// Cryptographic jobs and completion slots.
    CryptoJobs,
    /// Storage jobs and completion slots.
    StoreJobs,
    /// Finite owner, timer and operation metadata.
    Metadata,
}

/// Fresh identity of one live budget, independent of public process identifiers.
/// Node integrations supply their private entropy-derived instance nonce. Independent live ledgers
/// must never reuse a nonce; constructing this value alone reserves no storage.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BudgetOwner([u8; 16]);

impl BudgetOwner {
    /// Validate an explicitly supplied fresh, nonzero budget nonce.
    pub fn new(nonce: [u8; 16]) -> Result<Self, Error> {
        if nonce == [0; 16] {
            return Err(Error::InvalidInput);
        }
        Ok(Self(nonce))
    }
}

impl core::fmt::Debug for BudgetOwner {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        output.write_str("BudgetOwner(REDACTED)")
    }
}

/// Two distinct physical dimensions within one resource partition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PartitionUsage {
    /// Actual retained pool/storage bytes, including declared block rounding.
    pub bytes: Bytes,
    /// Actual finite storage, job or completion slots. Zero never means unlimited.
    pub slots: MessageSlots,
}

impl PartitionUsage {
    /// No bytes and no slots.
    pub const ZERO: Self = Self {
        bytes: Bytes(0),
        slots: MessageSlots(0),
    };
    /// Compose costs without mixing bytes and slot counts.
    pub fn checked_add(self, other: Self) -> Result<Self, Error> {
        Ok(Self {
            bytes: self.bytes.checked_add(other.bytes)?,
            slots: self.slots.checked_add(other.slots)?,
        })
    }
    /// Subtract both dimensions, rejecting underflow.
    pub fn checked_sub(self, other: Self) -> Result<Self, Error> {
        Ok(Self {
            bytes: self.bytes.checked_sub(other.bytes)?,
            slots: self.slots.checked_sub(other.slots)?,
        })
    }
    /// Whether this capacity covers both requested dimensions.
    pub const fn contains(self, other: Self) -> bool {
        self.bytes.0 >= other.bytes.0 && self.slots.0 >= other.slots.0
    }
}

/// Complete seven-partition physical cost or capacity. It grants no authority by itself.
/// Rows follow `Partition`'s declared order. Work/crypto CPU units and airtime remain separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartitionCost {
    partitions: [PartitionUsage; 7],
}

impl Default for PartitionCost {
    fn default() -> Self {
        Self::ZERO
    }
}

impl PartitionCost {
    /// No charge in any partition.
    pub const ZERO: Self = Self {
        partitions: [PartitionUsage::ZERO; 7],
    };
    /// A complete explicit profile, in `Partition` declaration order.
    pub const fn from_partitions(partitions: [PartitionUsage; 7]) -> Self {
        Self { partitions }
    }
    /// Quote one partition; every other row remains zero.
    pub const fn single(partition: Partition, usage: PartitionUsage) -> Self {
        let mut partitions = [PartitionUsage::ZERO; 7];
        partitions[partition as usize] = usage;
        Self { partitions }
    }
    /// Read one explicitly typed row.
    pub const fn get(self, partition: Partition) -> PartitionUsage {
        self.partitions[partition as usize]
    }
    /// Compose all fourteen dimensions with checked arithmetic and no state changes.
    pub fn checked_add(self, other: Self) -> Result<Self, Error> {
        let mut result = Self::ZERO;
        for index in 0..7 {
            result.partitions[index] =
                self.partitions[index].checked_add(other.partitions[index])?;
        }
        Ok(result)
    }
    /// Compose a fixed number of distinct backing owners in all fourteen dimensions.
    /// This only scales a description; it creates no spending or release authority.
    pub fn checked_mul(self, copies: u32) -> Result<Self, Error> {
        let mut result = Self::ZERO;
        for index in 0..7 {
            let usage = self.partitions[index];
            result.partitions[index] = PartitionUsage {
                bytes: Bytes(
                    usage
                        .bytes
                        .0
                        .checked_mul(u64::from(copies))
                        .ok_or(Error::Overflow)?,
                ),
                slots: MessageSlots(usage.slots.0.checked_mul(copies).ok_or(Error::Overflow)?),
            };
        }
        Ok(result)
    }
    /// Subtract all dimensions; underflow leaves both values unchanged.
    pub fn checked_sub(self, other: Self) -> Result<Self, Error> {
        let mut result = Self::ZERO;
        for index in 0..7 {
            result.partitions[index] =
                self.partitions[index].checked_sub(other.partitions[index])?;
        }
        Ok(result)
    }
    /// Component-wise capacity required by either alternative, without adding mutually exclusive work.
    pub const fn component_max(self, other: Self) -> Self {
        let mut result = Self::ZERO;
        let mut index = 0;
        while index < 7 {
            let a = self.partitions[index];
            let b = other.partitions[index];
            result.partitions[index] = PartitionUsage {
                bytes: Bytes(if a.bytes.0 > b.bytes.0 {
                    a.bytes.0
                } else {
                    b.bytes.0
                }),
                slots: MessageSlots(if a.slots.0 > b.slots.0 {
                    a.slots.0
                } else {
                    b.slots.0
                }),
            };
            index += 1;
        }
        result
    }
    /// Cover every partition and dimension; no cross-partition borrowing is permitted.
    pub const fn contains(self, other: Self) -> bool {
        let mut index = 0;
        while index < 7 {
            if !self.partitions[index].contains(other.partitions[index]) {
                return false;
            }
            index += 1;
        }
        true
    }
}

/// A single-use resource capability. Forgetting it retains the charge until owner recovery.
/// Splitting transfers only already charged capacity; it cannot increase the issuing budget.
#[derive(Debug)]
#[must_use]
pub struct Reservation {
    owner: BudgetOwner,
    cost: PartitionCost,
}

impl Reservation {
    /// Opaque identity for checking a child owner's exact issuing instance.
    pub const fn owner(&self) -> BudgetOwner {
        self.owner
    }
    /// Read-only cost metadata; copying it cannot refund resources.
    pub const fn cost(&self) -> PartitionCost {
        self.cost
    }
    /// Transfer part of this existing charge. All dimensions are checked before changing the
    /// remainder; failure preserves this capability. Neither branch changes total budget usage.
    pub fn split(&mut self, part: PartitionCost) -> Result<Self, Error> {
        if !self.cost.contains(part) {
            return Err(Error::Capacity);
        }
        let remainder = self.cost.checked_sub(part)?;
        self.cost = remainder;
        Ok(Self {
            owner: self.owner,
            cost: part,
        })
    }
}

/// One ledger for seven independently backed resource classes and their byte/slot dimensions.
/// It is arithmetic and ownership accounting, not storage allocation or a protocol scheduler.
/// The caller must supply actual backing and must not clone its identity into another live ledger.
pub struct PartitionBudget {
    owner: BudgetOwner,
    limits: PartitionCost,
    used: PartitionCost,
}

impl PartitionBudget {
    /// Bind one unique instance identity to explicit physically backed limits.
    #[must_use]
    pub const fn new(owner: BudgetOwner, limits: PartitionCost) -> Self {
        Self {
            owner,
            limits,
            used: PartitionCost::ZERO,
        }
    }
    /// Opaque issuing identity; Node budgets use the private Node instance nonce.
    pub const fn owner(&self) -> BudgetOwner {
        self.owner
    }
    /// Actual configured capacity; these values do not allocate backing storage.
    pub const fn limits(&self) -> PartitionCost {
        self.limits
    }
    /// Currently reserved/owned capacity, including split portions held by child owners.
    pub const fn used(&self) -> PartitionCost {
        self.used
    }
    /// Atomically reserve a complete cost. Overflow or any insufficient dimension changes nothing.
    pub fn try_acquire(&mut self, cost: PartitionCost) -> Result<Reservation, Error> {
        let used = self.used.checked_add(cost)?;
        if !self.limits.contains(used) {
            return Err(Error::Capacity);
        }
        self.used = used;
        Ok(Reservation {
            owner: self.owner,
            cost,
        })
    }
    /// Release one original capability. Foreign identity or invalid subtraction returns it intact
    /// and changes no dimension; byte/slot metadata alone cannot authorize a release.
    #[expect(
        clippy::result_large_err,
        reason = "A no-allocator rejection returns the complete noncloneable seven-partition reservation."
    )]
    pub fn release(&mut self, reservation: Reservation) -> Result<(), Rejected<Reservation>> {
        if reservation.owner != self.owner {
            return Err(Rejected {
                value: reservation,
                reason: Error::StaleGeneration,
            });
        }
        let used = match self.used.checked_sub(reservation.cost) {
            Ok(used) => used,
            Err(reason) => {
                return Err(Rejected {
                    value: reservation,
                    reason,
                });
            }
        };
        self.used = used;
        Ok(())
    }
    /// Remaining bytes and slots for one independently accounted resource class.
    pub const fn available(&self, partition: Partition) -> PartitionUsage {
        let limits = self.limits.get(partition);
        let used = self.used.get(partition);
        PartitionUsage {
            bytes: Bytes(limits.bytes.0 - used.bytes.0),
            slots: MessageSlots(limits.slots.0 - used.slots.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(bytes: u64, slots: u32) -> PartitionUsage {
        PartitionUsage {
            bytes: Bytes(bytes),
            slots: MessageSlots(slots),
        }
    }

    #[test]
    fn control_reserve_survives_data_exhaustion() -> Result<(), Error> {
        let owner = BudgetOwner::new([1; 16])?;
        let mut budget =
            PartitionBudget::new(owner, PartitionCost::from_partitions([usage(1, 1); 7]));
        let data_cost = PartitionCost::single(Partition::RecordProgress, usage(1, 1));
        let data = budget.try_acquire(data_cost)?;
        let control = budget.try_acquire(PartitionCost::single(
            Partition::ControlReserve,
            usage(1, 1),
        ))?;
        if budget.try_acquire(data_cost).is_ok() {
            return Err(Error::InvalidInput);
        }
        budget.release(control).map_err(|r| r.reason)?;
        budget.release(data).map_err(|r| r.reason)?;
        if budget.used() != PartitionCost::ZERO {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions verify every insufficient dimension leaves the whole live ledger unchanged."
    )]
    fn every_partition_byte_or_slot_failure_is_atomic() -> Result<(), Error> {
        for row in 0..7 {
            for dimension in 0..2 {
                let mut budget = PartitionBudget::new(
                    BudgetOwner::new([2; 16])?,
                    PartitionCost::from_partitions([usage(10, 2); 7]),
                );
                let original =
                    budget.try_acquire(PartitionCost::from_partitions([usage(7, 1); 7]))?;
                let before = budget.used();
                let mut costs = [usage(1, 0); 7];
                costs[row] = if dimension == 0 {
                    usage(4, 0)
                } else {
                    usage(0, 2)
                };
                assert!(matches!(
                    budget.try_acquire(PartitionCost::from_partitions(costs)),
                    Err(Error::Capacity)
                ));
                assert_eq!(budget.used(), before);
                budget.release(original).map_err(|r| r.reason)?;
                let exact = budget.try_acquire(budget.limits())?;
                assert_eq!(budget.used(), budget.limits());
                budget.release(exact).map_err(|r| r.reason)?;
                assert_eq!(budget.used(), PartitionCost::ZERO);
            }
        }
        let mut zero = PartitionBudget::new(BudgetOwner::new([3; 16])?, PartitionCost::ZERO);
        assert!(matches!(
            zero.try_acquire(PartitionCost::single(Partition::Metadata, usage(0, 1))),
            Err(Error::Capacity)
        ));
        assert!(matches!(
            zero.try_acquire(PartitionCost::single(Partition::Metadata, usage(1, 0))),
            Err(Error::Capacity)
        ));
        assert!(matches!(
            BudgetOwner::new([0; 16]),
            Err(Error::InvalidInput)
        ));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions distinguish byte/slot overflow from capacity and check no partial writes."
    )]
    fn composite_overflow_preserves_all_preexisting_reservations() -> Result<(), Error> {
        for dimension in 0..2 {
            let limit = PartitionCost::from_partitions([usage(u64::MAX, u32::MAX); 7]);
            let mut budget = PartitionBudget::new(BudgetOwner::new([4; 16])?, limit);
            let amount = if dimension == 0 {
                usage(u64::MAX, 0)
            } else {
                usage(0, u32::MAX)
            };
            let original =
                budget.try_acquire(PartitionCost::single(Partition::Metadata, amount))?;
            let before = budget.used();
            assert!(matches!(
                budget.try_acquire(PartitionCost::from_partitions([usage(1, 1); 7])),
                Err(Error::Overflow)
            ));
            assert_eq!(budget.used(), before);
            budget.release(original).map_err(|r| r.reason)?;
        }
        let a = PartitionCost::single(Partition::CryptoJobs, usage(128, 1));
        let b = PartitionCost::single(Partition::CryptoJobs, usage(16, 3));
        assert_eq!(a.component_max(b).get(Partition::CryptoJobs), usage(128, 3));
        assert_eq!(a.checked_add(b)?.get(Partition::CryptoJobs), usage(144, 4));
        Ok(())
    }

    #[test]
    fn fixed_owner_multiplication_checks_every_dimension_without_changing_the_quote()
    -> Result<(), Error> {
        let original = PartitionCost::from_partitions([usage(19, 3); 7]);
        if original.checked_mul(0)? != PartitionCost::ZERO
            || original.checked_mul(1)? != original
            || original.checked_mul(4)? != PartitionCost::from_partitions([usage(76, 12); 7])
            || PartitionCost::ZERO.checked_mul(u32::MAX)? != PartitionCost::ZERO
        {
            return Err(Error::Conflict);
        }
        for index in 0..7 {
            for amount in [usage(u64::MAX, 0), usage(0, u32::MAX)] {
                let mut parts = [PartitionUsage::ZERO; 7];
                parts[index] = amount;
                let quote = PartitionCost::from_partitions(parts);
                if quote.checked_mul(2) != Err(Error::Overflow)
                    || quote != PartitionCost::from_partitions(parts)
                {
                    return Err(Error::Conflict);
                }
            }
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions verify split conservation and foreign capabilities return without mutating either budget."
    )]
    fn split_transfers_existing_charge_and_foreign_release_returns_it() -> Result<(), Error> {
        let device = PartitionCost::single(Partition::RecordProgress, usage(128, 1));
        let crypto = PartitionCost::single(Partition::CryptoJobs, usage(64, 1));
        let total = device.checked_add(crypto)?;
        let mut budget = PartitionBudget::new(BudgetOwner::new([5; 16])?, total);
        let mut other = PartitionBudget::new(BudgetOwner::new([6; 16])?, total);
        let mut root = budget.try_acquire(total)?;
        assert!(matches!(
            root.split(PartitionCost::single(
                Partition::RecordProgress,
                usage(129, 1)
            )),
            Err(Error::Capacity)
        ));
        assert_eq!(root.cost(), total);
        let child = root.split(device)?;
        assert_eq!(root.cost(), crypto);
        assert_eq!(budget.used(), total);
        let rejected = match other.release(child) {
            Ok(()) => return Err(Error::Conflict),
            Err(rejected) => rejected,
        };
        assert_eq!(rejected.reason, Error::StaleGeneration);
        assert_eq!(rejected.value.cost(), device);
        assert_eq!(other.used(), PartitionCost::ZERO);
        assert_eq!(budget.used(), total);
        budget.release(rejected.value).map_err(|r| r.reason)?;
        assert_eq!(budget.used(), crypto);
        budget.release(root).map_err(|r| r.reason)?;
        assert_eq!(budget.used(), PartitionCost::ZERO);
        Ok(())
    }
}
