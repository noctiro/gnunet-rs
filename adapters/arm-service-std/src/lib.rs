//! Actual ARM service host: registry, managed listeners and a borrowed reactor.
//! Native process operations use the single shared service-runtime backend.
//! The optional production service module composes shared SERVICE startup,
//! selected logging and real native supervision; early foreign-fd/fork capture
//! remains in the fresh main process. Readiness is never manufactured.
#![cfg(unix)]
#![forbid(unsafe_code)]
pub mod addresses;
pub mod listeners;
pub mod registry;

/// Bounded persistent official stream framing used by the daemon reactor.
pub mod framed;

/// Actual borrowed daemon reactor using the single shared process port.
pub mod reactor;

/// Production standalone SERVICE startup, selected logging and actual native
/// ARM supervision. Early descriptor/fork boundaries remain in the tiny app.
#[cfg(feature = "service")]
pub mod service;
