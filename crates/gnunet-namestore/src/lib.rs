//! Pure NAMESTORE label/record policy and explicit authority transaction state.
//! No database, IPC owner, entropy, key file, resolver or scheduler is created.
#![no_std]
#![forbid(unsafe_code)]
mod policy;
pub use gnunet_gnsrecord::{RecordData, RecordFlags, RecordSet, RecordType, ZoneKey};
pub use gnunet_identity::{SecretKey, SecretKeyView};
pub use policy::*;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod inventory;
#[cfg(feature = "alloc")]
pub use inventory::*;
#[cfg(feature = "alloc")]
mod streams;
#[cfg(feature = "alloc")]
pub use streams::*;
