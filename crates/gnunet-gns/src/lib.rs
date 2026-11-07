//! GNS authority, name and recursive record-processing ownership.
//!
//! Default builds allocate nothing. The `alloc` feature provides a bounded,
//! event-driven multi-query resolver; it performs cryptography itself and
//! issues original typed dependency effects, without sockets or a scheduler.
//! DNS and operating-system effects are explicit trust boundaries, never GNS
//! block authentication shortcuts. IPC framing belongs to `gnunet-client`.
#![no_std]
#![forbid(unsafe_code)]
pub mod assigned;
#[cfg(feature = "alloc")]
extern crate alloc;
mod names;
pub use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType, ZoneKey};
pub use gnunet_types::Error;
pub use names::{Mapping, StartZone, select_start_zone, validate_name};
#[cfg(feature = "alloc")]
mod records;
#[cfg(feature = "alloc")]
mod resolver;
#[cfg(feature = "alloc")]
pub use records::{Origin, Record, address_literal};
#[cfg(feature = "alloc")]
pub use resolver::{
    CACHE_REFRESH_THRESHOLD, CacheRefresh, Effect, EffectId, EffectKind, Failure, Instance, Limits,
    Lookup, Policy, QueryId, Resolver,
};
