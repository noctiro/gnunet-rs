//! Frozen display output and independent terminal accounting.
mod render;
mod report;
mod writer;
pub(super) use render::{joined, message, welcome};
pub(super) use report::*;
pub(super) use writer::{Writer, Written};
