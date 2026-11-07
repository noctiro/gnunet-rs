//! Actual781 decrypt and original780 generation over their native owners.
//! The general FAIR response-width obstruction remains an explicit failure.
#![forbid(unsafe_code)]
mod generate;
mod run;
mod server;
mod types;
pub use server::Server;
pub use types::*;
