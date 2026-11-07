//! Compatibility path for the shared qualified raw snapshot worker.
//! IDENTITY startup explicitly selects Namespace::Identity; no business state
//! or private-key file format is interpreted by this shared runtime layer.
pub use gnunet_snapshot_host::worker::*;
