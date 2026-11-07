//! Caller-selected actual DHT ownership; no default or successful dummy provider.
use crate::{Failure, Settings};
use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution::SharedResolution};
use gnunet_regex_server_host::dht::Provider;
use gnunet_service_runtime::clock::RuntimeClock;
use std::sync::Arc;
use tokio::time::Instant;
/// Post-fork, target-account, active-runtime construction context.
/// Borrowed storage is outside the provider/Driver and outlives all its debts.
pub struct Context<'a, S> {
    /// Factory's stable caller-owned instances, slots or process resources.
    pub storage: &'a mut S,
    /// The actual selected SERVICE configuration, shared by all clients.
    pub configuration: LiveConfiguration,
    /// Actual shared Resolver provider; no hidden system resolver is substituted.
    pub resolution: SharedResolution,
    /// Original configured DHT endpoint using this same Resolver and clock.
    pub endpoint: EndpointSource,
    /// Exact original canonical clock authority, not an equivalent fresh source.
    pub clock: Arc<dyn RuntimeClock>,
    /// First startup native deadline, never renewed by connection attempts.
    pub startup_until: Instant,
    /// Validated finite frontend capacities and phase bounds.
    pub settings: &'a Settings,
}
/// Static construction policy. No factory value crosses fork/USERNAME.
///
/// `storage` and `create` run only in the service process after account switching,
/// listener finish, runtime creation and actual shared Resolver construction.
/// The returned provider must retain every original operation through close and
/// report `is_closed` only after its own physical/native/worker debts retire.
/// `create` must leave no detached task on error. A provider may borrow storage;
/// it may not borrow/move itself or install hidden tasks.
pub trait Factory: 'static {
    /// Stable storage placed outside the borrowed actual provider.
    type Storage;
    /// One real original provider, borrowing only the outer caller's storage.
    type Provider<'a>: Provider
    where
        Self: 'a;
    /// Allocate actual empty caller storage after process/runtime preparation.
    fn storage() -> Result<Self::Storage, Failure>;
    /// Construct the real provider. No request is made by the frontend before
    /// Driver construction; constructor failure must retire its own resources.
    fn create<'a>(context: Context<'a, Self::Storage>) -> Result<Self::Provider<'a>, Failure>;
    /// Inspect the exact owned provider's current native readiness. This is not
    /// a generic trait default or a promise that future DHT operations succeed.
    fn ready(provider: &Self::Provider<'_>) -> Result<bool, Failure>;
}
