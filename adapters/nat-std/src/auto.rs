//! Active pinned NAT-auto production behavior: propose ENABLE_UPNP based on
//! actual available implementation, without pretending to classify reachability.
use gnunet_config::Configuration;
use gnunet_types::Error as Fault;
use gnunet_wire::official::nat_auto::{NatType, Status};
/// Actual bounded serialized proposal, not a receipt of system configuration.
#[derive(Debug)]
pub struct Proposal {
    /// Actual local autoconfiguration status.
    pub status: Status,
    /// Unknown until a real reachability test is performed.
    pub nat_type: NatType,
    /// Actual GNUnet serialized configuration diff.
    pub configuration_diff: Vec<u8>,
}
/// Propose the actual compiled Rust IGD backend's availability. The C active
/// daemon merely checks the external upnpc executable; Rust has a real built-in
/// backend instead. No map, connectivity, root helper or config write is inferred.
pub fn propose(
    template: &Configuration,
    serialized: &[u8],
) -> Result<Proposal, Box<dyn std::error::Error>> {
    if serialized.len() > 65531 {
        return Err(Fault::TooLarge.into());
    }
    let mut original = Configuration::create(
        std::sync::Arc::new(template.project_data().clone()),
        Default::default(),
    )?;
    original.deserialize(serialized, None)?;
    let mut updated = original.duplicate()?;
    updated.set_value(b"nat", b"ENABLE_UPNP", Some(b"YES"))?;
    let diff = original.diff(&updated)?.serialize()?;
    if diff.len() > 65523 {
        return Err(Fault::TooLarge.into());
    }
    Ok(Proposal {
        status: Status::SUCCESS,
        nat_type: NatType::UNKNOWN,
        configuration_diff: diff,
    })
}
