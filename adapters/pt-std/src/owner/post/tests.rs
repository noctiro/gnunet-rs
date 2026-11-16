//! POST construction and separate enabled IPC models.
use super::*;
use crate::{Identities, Limits, Sources};
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use std::sync::Arc;

#[cfg(feature = "program")]
mod runtime;

#[test]
fn post_only_owner_needs_no_cadet_storage_or_disabled_provider_capacity() -> Result<(), Failure> {
    let core = gnunet_pt::core::Instance::new();
    let dns = gnunet_dns_client_host::Instance::new();
    let mut vpn = vpn::Instance::new();
    let mut cadet = super::super::cadet::Instance::new();
    let mut ports = [];
    let mut channels = [];
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let endpoint = |name| {
        gnunet_client_host::EndpointSource::unix_with_clock(
            std::path::PathBuf::from(name),
            clock.clone(),
        )
    };
    let mut native = Limits::default();
    native.cadet.frame_bytes = 0;
    let mut owner = Owner::new(
        Identities {
            core: &core,
            dns: &dns,
            vpn: &mut vpn,
            cadet: &mut cadet,
            ports: &mut ports,
            channels: &mut channels,
        },
        Sources {
            pre: None,
            post: Some(endpoint("unused-pt-post-dns")),
            vpn: Some(endpoint("unused-pt-post-vpn")),
            cadet: None,
            discovery: None,
        },
        clock,
        gnunet_pt::core::Limits::default(),
        gnunet_pt::packet::Families {
            ipv4: true,
            ipv6: true,
        },
        native,
        vpn::AfProfile::native(),
    )?;
    if !owner.stop().is_empty() {
        return Err("unconnected POST-only owner produced cleanup failure".into());
    }
    Ok(())
}
