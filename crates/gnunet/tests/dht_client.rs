//! Feature-only SDK entrypoint. No socket, Runtime or Resolver is started.
#![cfg(all(feature = "official-dht-client", unix))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "SDK entrypoint exercises original owners and offline admission."
)]
use gnunet::clients::dht::{Cancel, Client, EndpointSource, Get, Instance, Limits, Monitor};
use gnunet::clients::dht::{
    clock,
    resolution::{AddressLookup, ResolutionContext, ResolutionTimer},
};
use std::{io, sync::Arc, time::Duration};
struct ExplicitPorts;
impl ResolutionContext for ExplicitPorts {
    fn clock(&self) -> Arc<dyn clock::RuntimeClock> {
        Arc::new(clock::SystemClock)
    }
    fn lookup(&self, _: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        Err(io::Error::other(
            "No Resolver lookup in this SDK surface test",
        ))
    }
    fn timer(&self, _: Duration) -> io::Result<ResolutionTimer> {
        Err(io::Error::other("No timer in this SDK surface test"))
    }
}
#[test]
fn optional_dht_facade_admits_and_cancels_offline_without_hidden_runtime()
-> Result<(), Box<dyn std::error::Error>> {
    let ports: Arc<dyn ResolutionContext> = Arc::new(ExplicitPorts);
    let _clock = ports.clock();
    let _live: Option<gnunet::clients::dht::LiveConfiguration> = None;
    let mut instance = Instance::new();
    let mut client = Client::new(
        &mut instance,
        EndpointSource::unix(std::path::PathBuf::from("/unused-sdk-dht")),
        Limits::default(),
    )?;
    let get = client.get(Get {
        key: &[0; 64],
        block_type: 8,
        options: 0,
        replication: 1,
        extended_query: &[],
    })?;
    assert_eq!(client.request_id(get)?.0, [0; 8]);
    client.known(get, &[[7; 64]])?;
    let hello = client.hello()?;
    let monitor = client.monitor(Monitor {
        block_type: 0,
        get: 1,
        result: 1,
        put: 1,
        key: None,
    })?;
    assert_eq!(client.stop(get)?, Cancel::BeforeIssue);
    assert_eq!(client.cancel_hello(hello)?, Cancel::BeforeIssue);
    assert_eq!(client.stop_monitor(monitor)?, Cancel::BeforeIssue);
    assert!(client.epoch().is_none());
    assert_eq!(client.snapshot().attempts, 0);
    assert_eq!(client.snapshot().source_bytes, 0);
    assert!(client.close().is_none());
    assert!(client.snapshot().closed);
    Ok(())
}
