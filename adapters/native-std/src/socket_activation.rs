//! Native Windows listener sharing, independent of GNUnet service/network frames.
mod export;
mod incoming;
mod mapping;
mod record;
pub use export::AccountExportSection;
pub use export::BootstrapGrant;
pub use export::ExportSection;
pub use export::Publication;
pub use export::PublishFailure;
pub use export::Source;
pub(crate) use export::{Admission, Delivery};
pub use incoming::{ImportedSocket, Incoming};
pub use record::MAX_LISTENERS;

/// Prefix of a managed account's inherited handle and publisher SID declaration.
pub const ACCOUNT_HANDLE_PREFIX: &str = "account:";

/// Prefix of a cross-session activation verifier in the original launch.
pub const BOOTSTRAP_KEY_PREFIX: &str = "brokered-v1:";
