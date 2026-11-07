//! Bounded caller-driven implementation of GNUnet's public utility UDP burst API.
//! The default socket is never read here. Its dispatcher passes original input to
//! [`Burst::on_datagram`]; newly bound scan sockets forward unrelated data through
//! [`Event::Datagram`]. A selection is only an unauthenticated socket observation.
#![cfg(unix)]
#![forbid(unsafe_code)]
mod driver;
mod types;
pub use driver::Burst;
pub use gnunet_nat::burst as wire;
pub use types::*;
#[cfg(test)]
mod model;
