//! Bounded official Messenger room, member/session, message/DAG, discourse and
//! epoch/group state. Native ports supply actual source outcomes; no hidden I/O.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
mod types;
pub use types::*;
mod custody;
#[cfg(feature = "alloc")]
pub use custody::OwnedBytes;
pub use custody::{
    BorrowedBytes, ByteSlot, OriginalBytes, OriginalId, OriginalPool, OriginalPoolInstance,
    OriginalSlot, OriginalStorage,
};

mod apply;
#[cfg(feature = "alloc")]
mod bootstrap;
#[cfg(feature = "alloc")]
mod drive;
mod engine;
mod epoch;
mod graph;
mod identity;
mod ingest;
#[cfg(feature = "alloc")]
mod key_controls;
mod lease;
mod message_index;
mod outgoing;
mod room_history;
mod room_queues;
mod room_ring;
mod room_storage;
mod room_tables;
mod slot_queue;
mod slots;
mod state;
mod storage;
pub use engine::*;
pub use epoch::members::EpochMemberCell;
pub use gnunet_messenger::{SensitiveBuffer, carrier, crypto, wire};
pub use graph::{CommittedServiceOriginal, History, HistoryCell, HistoryWorkspace, MessageRef};
pub use room_history::{HistoryNodeCell, RoomHistoryStorage};
pub use room_queues::{RoomPeerCell, RoomQueueStorage};
pub use room_ring::{RingNeighbor, RingRole, ServiceConnection, ServiceRoomRing};
pub use room_storage::ServiceRoomStorage;
pub use room_tables::{
    EpochCell, MissingCell, OperationCell, RoomTableStorage, SessionCell, SourceCell,
    SubscriptionCell,
};
pub use state::{
    Binding, BindingObservation, ContactCell, Encoding, EpochAliasCell, Event, EventCell,
    EventObservation, NativePurpose, OperationPhase,
};
#[cfg(all(test, feature = "alloc"))]
mod model;
#[cfg(feature = "alloc")]
pub use state::RejectedInput;

mod service;
pub use service::{
    ServiceAttribution, ServiceBootstrap, ServiceHistoryItem, ServiceLocalOriginal,
    ServiceRequestAuthority, ServiceRequestOriginal, ServiceState,
};
mod service_admission;
pub use service_admission::{
    ClientSend, EntryRoute, EntryStep, EntryTarget, LocalEntry, LocalRequest, LocalRoomAdmission,
    LocalRoomCommand, LocalRoomRequest, LocalSend, PeerHandshake, RemoteDoor, RoomCapabilities,
    ScopedLocalRoomRequest,
};

mod service_routing;
pub use service_routing::ServiceMerge;

mod layout;
pub use layout::{BodyLayout, OriginalLayout, OriginalSigner};

pub mod archive;

mod client_layout;
mod committed_archive;
pub use committed_archive::CommittedArchive;
#[cfg(feature = "alloc")]
mod recipient;
pub use client_layout::{ClientLayout, EpochRecordTarget, ShortLayout};
#[cfg(feature = "alloc")]
pub use recipient::{RecipientAttribution, RecipientEvidence};
