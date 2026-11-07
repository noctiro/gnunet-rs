//! Caller-driven ordinary DNS2GNS gateway with original per-query owners.
//! There are no background tasks, threads, implicit Resolver or DNS fallback on
//! GNS failure. A complete UDP send is not peer processing or a VPN lease revoke.
#![forbid(unsafe_code)]
pub mod packet;
mod types;
pub use types::*;
mod budget;
mod request;
mod runtime;
pub use runtime::Runtime;
