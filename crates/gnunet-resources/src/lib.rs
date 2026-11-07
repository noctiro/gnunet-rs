//! Fixed-capacity packets, local immutable leases, finite owners and resource accounting.
//!
//! Each internal module owns one resource mechanism. Public types are exposed here so
//! callers compose packets, slots, deadlines and physical budgets without module coupling.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod budget;
mod lease;
mod packet;
mod queue;
mod slot;
mod timer;

pub use budget::{
    BudgetOwner, Partition, PartitionBudget, PartitionCost, PartitionUsage, Reservation,
};
pub use lease::{FrameLease, LeaseSource};
pub use packet::{FixedResources, Frame, FrameMut, FrameView, PacketChain, ResourceSet, SealPlan};
#[cfg(feature = "alloc")]
pub use packet::{HostPacket, HostResources};
pub use queue::BoundedQueue;
pub use slot::{SlotCheckpoint, SlotTable};
pub use timer::TimerWheel;
