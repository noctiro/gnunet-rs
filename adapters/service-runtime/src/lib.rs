//! Shared Unix host startup for official GNUnet services.
//!
//! Inherited descriptor capture must happen before runtime/configuration setup.
//! Binding uses explicit service sections, owns only paths it creates, and keeps
//! listener lifetime ahead of path cleanup. Protocol handlers remain in their
//! service crates; this package implements neither daemonization nor user switching.
#![cfg(unix)]

/// Original accepted-stream ownership and socket diagnostics.
pub mod accepted;
/// Official service address admission policy.
pub mod acl;
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
mod native_spawn;
/// Official Unix address shaping shared by clients and service hosts.
pub mod network;
mod path;
/// Native command preparation, original child/control ownership and exec helper.
pub mod process;
/// Opaque owned descriptor registration and nonconsuming readiness.
pub mod readiness;
/// Borrowed listeners and service policies, independent of protocol engines.
pub mod service;
mod stream;

pub use activation::{
    ActivatedSocket, Activation, PrivateListener, bind_private, bind_private_with_backlog,
    bind_private_with_permissions, capture,
};
pub use listeners::{BoundListeners, ListenerPreparation, UnixListenerAccess, service_options};
pub use path::{CreatedPath, private_parents};
