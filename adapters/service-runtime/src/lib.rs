//! Shared native runtime for official GNUnet services.
//!
//! Inherited descriptor capture must happen before runtime/configuration setup.
//! Binding uses explicit service sections, owns only paths it creates, and keeps
//! listener lifetime ahead of path cleanup. Protocol handlers remain in their
//! service crates; this package implements neither daemonization nor user switching.

/// Original accepted-stream ownership and socket diagnostics.
pub mod accepted;
/// Official service address admission policy.
pub mod acl;
#[cfg(any(unix, windows))]
pub mod activation;
/// Logical time source, subscriptions and caller-owned deadline futures.
pub mod clock;
/// Unique Unix/TCP streams and explicit dependent lifetime leases.
pub mod connection;
/// Shared kernel Unix credential admission policy.
pub mod credentials;
/// Persistent secure framing and original immutable FIFO ownership.
pub mod framing;
mod listeners;
/// Native AF_UNIX reactor streams and listeners; filesystem/peer policy is separate.
pub mod local;
/// Private local listener preparation before choosing a reactor owner.
#[cfg(any(unix, windows))]
pub mod local_listener;
#[cfg(unix)]
mod native_spawn;
/// Official AF_UNIX address shaping shared by clients and service hosts.
#[cfg(any(unix, windows))]
pub mod network;
#[cfg(any(unix, windows))]
mod path;
/// Private Windows parent/child byte channels with explicit submission receipts.
#[cfg(windows)]
pub mod pipe;
/// Native command preparation, original child/control ownership and exec helper.
#[cfg(any(unix, windows))]
pub mod process;
/// Owned socket/descriptor registration and nonconsuming readiness.
#[cfg(any(unix, windows))]
pub mod readiness;
/// Borrowed listeners and service policies, independent of protocol engines.
pub mod service;
/// Native process stop sources registered after console detachment.
#[cfg(any(unix, windows))]
pub mod signals;
mod stream;

#[cfg(windows)]
pub use activation::ActivatedSocket;
#[cfg(windows)]
pub use activation::Activation;
#[cfg(unix)]
pub use activation::{
    ActivatedSocket, Activation, PrivateListener, bind_private, bind_private_with_backlog,
    bind_private_with_permissions, capture,
};
pub use listeners::BoundListeners;
#[cfg(unix)]
pub use listeners::ListenerPreparation;
pub use listeners::LocalListenerAccess;
pub use listeners::service_options;
#[cfg(any(unix, windows))]
pub use path::{CreatedPath, private_parents};
