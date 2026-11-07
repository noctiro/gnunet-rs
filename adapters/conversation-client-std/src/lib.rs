//! Original caller-driven CONVERSATION Lines and bounded zeroizing media.
//! No implicit GNS lookup, identity, device, Resolver, worker or service is used.
#![forbid(unsafe_code)]
mod audio;
mod budget;
mod line;
mod types;
pub use budget::Bounds;
pub use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution};
pub use gnunet_service_runtime::clock;
pub use gnunet_wire::official::conversation as ipc;
pub use line::Line;
pub use types::{
    Audio, Call, CallInfo, Cause, Epoch, Error, Kind, Limits, Loss, Operation, Phase, Progress,
    Receipt, Role,
};
