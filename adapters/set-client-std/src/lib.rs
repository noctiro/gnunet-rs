//! Caller-driven active generic SET SDK over the original native service IPC.
//! No SETI/U substitution, service spawning, worker, private framing or fake ACK.
#![forbid(unsafe_code)]
mod budget;
mod events;
mod factory;
mod listener;
mod prepared;
mod session;
mod set;
mod types;
pub use budget::{Bounds, DeadlineContext, DeadlineScope, DeadlineWrite};
pub use events::{
    CancelDisposition, CancellationCause, CopyReceipt, IterationReceipt, MutationKind,
    MutationReceipt, OperationReceipt, SetLoss, SetProgress,
};
pub use factory::{CopyFailure, Factory};
pub use gnunet_client_host::EndpointSource;
pub use gnunet_wire::official::set::{Abi, Element, Options, Order};
pub use listener::{
    Decision, Incoming, ListenProgress, Listener, ListenerLoss, RejectFailure, RejectId,
};
pub use prepared::{CopyTicket, Prepared};
pub use session::TransportLoss;
pub use set::{CommitFailure, IterCancelDisposition, Set};
pub use types::{
    Cause, CopyId, ElementOwned, Epoch, Error, IterationId, Limits, LossOrigin, MutationId,
    OperationId, OperationType, ResultMode, Status,
};
fn encode(request: gnunet_wire::official::set::ClientRequest<'_>) -> Result<Vec<u8>, Error> {
    let size = request.encoded_len()?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| gnunet_types::Error::Capacity)?;
    bytes.resize(size, 0);
    request.encode(&mut bytes)?;
    Ok(bytes)
}
