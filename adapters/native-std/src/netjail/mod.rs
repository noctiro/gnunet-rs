//! Original Linux network namespace leases for private test topologies.

mod namespace;
mod nat;
mod route;

pub use namespace::{NetworkNamespace, PrivateNetworkNamespace, enter_fixture_user_namespace};
pub use nat::enable_ipv4_masquerade;
pub use route::{Ipv4Prefix, LinkName, RouteSocket};
