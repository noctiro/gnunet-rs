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
#[cfg(unix)]
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
#[cfg(unix)]
mod native_spawn;
/// Official Unix address shaping shared by clients and service hosts.
#[cfg(unix)]
pub mod network;
#[cfg(unix)]
mod path;
/// Native command preparation, original child/control ownership and exec helper.
#[cfg(unix)]
pub mod process;
/// Opaque owned descriptor registration and nonconsuming readiness.
#[cfg(unix)]
pub mod readiness;
/// Borrowed listeners and service policies, independent of protocol engines.
pub mod service;
mod stream;

#[cfg(unix)]
pub use activation::{
    ActivatedSocket, Activation, PrivateListener, bind_private, bind_private_with_backlog,
    bind_private_with_permissions, capture,
};
pub use listeners::{BoundListeners, service_options};
#[cfg(unix)]
pub use listeners::{ListenerPreparation, UnixListenerAccess};
#[cfg(unix)]
pub use path::{CreatedPath, private_parents};
