//! Bounded official Messenger room, member/session, message/DAG, discourse and
//! epoch/group state. Native ports supply actual source outcomes; no hidden I/O.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
mod types;
pub use types::*;
#[cfg(feature = "alloc")]
mod apply;
#[cfg(feature = "alloc")]
mod drive;
#[cfg(feature = "alloc")]
mod engine;
#[cfg(feature = "alloc")]
mod epoch;
#[cfg(feature = "alloc")]
mod graph;
#[cfg(feature = "alloc")]
mod identity;
#[cfg(feature = "alloc")]
mod ingest;
#[cfg(feature = "alloc")]
mod outgoing;
#[cfg(feature = "alloc")]
mod slots;
#[cfg(feature = "alloc")]
mod state;
#[cfg(feature = "alloc")]
pub use engine::*;
pub use gnunet_messenger::{SensitiveBuffer, crypto, wire};
#[cfg(feature = "alloc")]
pub use graph::{History, HistoryWorkspace, MessageRef};
#[cfg(feature = "alloc")]
pub use state::{
    Binding, BindingObservation, Encoding, Event, EventObservation, NativePurpose, OperationPhase,
    OwnedBytes, RejectedInput,
};
#[cfg(all(test, feature = "alloc"))]
mod model;

#[cfg(feature = "alloc")]
mod service;
#[cfg(feature = "alloc")]
pub use service::{ServiceAttribution, ServiceState};

#[cfg(feature = "alloc")]
mod service_routing;
#[cfg(feature = "alloc")]
pub use service_routing::ServiceMerge;

#[cfg(feature = "alloc")]
mod layout;
#[cfg(feature = "alloc")]
pub use layout::{BodyLayout, OriginalLayout, OriginalSigner};

#[cfg(feature = "alloc")]
pub mod archive;

#[cfg(feature = "alloc")]
mod client_layout;
#[cfg(feature = "alloc")]
mod recipient;
#[cfg(feature = "alloc")]
pub use client_layout::{ClientLayout, EpochRecordTarget, ShortLayout};
#[cfg(feature = "alloc")]
pub use recipient::{RecipientAttribution, RecipientEvidence};
