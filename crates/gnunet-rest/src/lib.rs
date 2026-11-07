//! Bounded caller-buffer HTTP and official GNUnet v0.29.1 REST contracts.
//! This pure crate opens no HTTP listener, service, key, clock or worker.
#![no_std]
#![forbid(unsafe_code)]
pub mod http;
pub mod route;

pub mod contracts;
pub mod text;

pub mod form;
#[cfg(feature = "oidc")]
pub mod oidc;
