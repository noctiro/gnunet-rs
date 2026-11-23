//! Bounded native receive injection of complete IPv4/IPv6 UDP DNS replies.
//!
//! Original reservations are published before native submission. Completion
//! owns accepted packets even when WFP completes before submission returns.
//! Native contracts: [receive injection](https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsinjecttransportreceiveasync0)
//! and [completion](https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_inject_complete0).

mod completion;
mod error;
mod packet;
mod pool;
mod resources;
mod submission;

pub use completion::{Completion, Target};
pub use error::Error;
pub use packet::PacketError;
pub use pool::Pool;
pub use submission::{Submission, Submitted};
