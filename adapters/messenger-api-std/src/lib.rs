//! Actual caller-driven high-level official Messenger client. Native service,
//! CADET relay and daemon authority remain distinct packages and processes.
#![forbid(unsafe_code)]
pub use domain::{
    Binding, Contact, Hash, History, HistoryWorkspace, MemberSession, MessageRef, Operation,
    PublicKey, Room, SensitiveBuffer, ShortHash, Source, crypto, wire,
};
pub use gnunet_client_host::EndpointSource;
pub use gnunet_gnsrecord_text as record_text;
pub use gnunet_messenger_client_host as native;
pub use gnunet_messenger_core as domain;
mod api;
mod clock;
mod discovery;
mod drive;
mod epochs;
mod io;
mod limits;
mod providers;
mod records;
mod recovery;
mod rooms;
mod subscriptions;
mod types;
pub use api::Api;
pub use clock::Deadline;
pub use discovery::{Discovery, DiscoveryProgress, RoomAnswer, RoomEntry, RoomQuery};
pub use limits::Limits;
pub use providers::{Identity, OsEntropy};
pub use records::{RecordDestination, RecordLimits, RecordLoss, RecordProgress};
pub use types::{
    Closing, ControlReport, Error, Exposure, JobReport, Loss, LossParts, PrivateSend, Progress,
    StopCause,
};

#[cfg(test)]
mod model;

mod layouts;
pub use domain::{
    ClientLayout, OriginalLayout, OriginalSigner, RecipientAttribution, RecipientEvidence,
    ShortLayout,
};
pub use layouts::{LayoutNeed, LayoutRequirement, Profiles};
