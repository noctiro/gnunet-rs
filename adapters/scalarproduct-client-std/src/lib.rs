//! Caller-driven official SCALARPRODUCT requester/responder IPC.
//! No computation service, crypto, service spawn or private protocol is supplied.
#![forbid(unsafe_code)]
mod client;
mod types;
pub use client::Client;
pub use gnunet_client_host::EndpointSource;
pub use gnunet_service_runtime::clock::Bounds;
pub use gnunet_wire::official::scalarproduct::{ELEMENT_BYTES, Element, ResponseStatus};
pub use types::{Cause, Epoch, Error, Limits, Loss, Progress, Receipt, Response, Role};
