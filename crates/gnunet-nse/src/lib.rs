//! Bounded pure NSE service protocol, cryptographic admission and estimator.
//! Native CORE/PILS/timers, entropy and proof persistence are explicit ports.
//!
//! ```
//! use gnunet_nse::owner::{Config, Instance, Service};
//! let mut instance = Instance::new();
//! let mut service = Service::<0, 1>::new(&mut instance, Config::default())?;
//! let subscriber = service.subscribe(&[0, 4, 1, 65])?;
//! let notification = service.next_notification(0)?.ok_or(gnunet_types::Error::NotReady)?;
//! service.notified(&notification)?;
//! service.unsubscribe(subscriber)?;
//! service.close();
//! # Ok::<(), gnunet_types::Error>(())
//! ```
//!
//! Original instance storage cannot move while its service is live:
//! ```compile_fail
//! use gnunet_nse::owner::{Config, Instance, Service};
//! let mut instance = Instance::new();
//! let service = Service::<0, 0>::new(&mut instance, Config::default()).unwrap();
//! let moved = instance;
//! let _ = service.summary();
//! ```
#![no_std]
#![forbid(unsafe_code)]
pub mod crypto;
pub mod history;
/// Bounded actual NSE observations and official metric names.
pub mod metrics;
pub mod owner;

#[cfg(test)]
extern crate std;
