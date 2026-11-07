//! Public SDK feature entrypoint only; no socket/remote processing credit.
#![cfg(all(feature = "official-pils-client", unix))]
use gnunet::{
    client_host::resolution::{AddressLookup, ResolutionContext, ResolutionTimer},
    clients::pils::{
        Client, EndpointSource, HelloLimits, Instance, KeyTarget, Limits, Profile, Progress, clock,
    },
};
use std::{io, path::PathBuf, sync::Arc, time::Duration};
struct ExplicitPorts;
impl ResolutionContext for ExplicitPorts {
    fn clock(&self) -> Arc<dyn clock::RuntimeClock> {
        Arc::new(clock::SystemClock)
    }
    fn lookup(&self, _: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        Err(io::Error::other("no lookup in SDK typecheck"))
    }
    fn timer(&self, _: Duration) -> io::Result<ResolutionTimer> {
        Err(io::Error::other("no timer in SDK typecheck"))
    }
}
#[test]
fn facade_names_native_owner_types_and_custom_canonical_ports_without_host_dependency()
-> Result<(), Box<dyn std::error::Error>> {
    let ports: Arc<dyn ResolutionContext> = Arc::new(ExplicitPorts);
    let _clock = ports.clock();
    let mut instance = Instance::new();
    let mut client = Client::<2>::new(
        &mut instance,
        EndpointSource::unix(PathBuf::from("/unused-sdk-pils")),
        Profile::Reference029,
        Limits {
            pending_operations: 2,
            ..Limits::default()
        },
        HelloLimits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 4096,
            maximum_addresses: 32,
        },
    )?;
    let operation = client.ecdh([7; 32], KeyTarget::ServiceCurrent)?;
    client.cancel(operation)?;
    let _event: Option<Progress<'_, 2>> = None;
    client.close();
    Ok(())
}
