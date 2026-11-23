//! Consume the actual old TRANSPORT source before scheduling its replacement.
use crate::{
    Cause,
    addresses::Addresses,
    bootstrap::Dial,
    diagnostics::{Diagnostics, Severity},
};
use gnunet_udp_communicator_host::communicator::{Communicator, IdentityRetirement};

pub(in crate::run) fn observe(
    owner: &mut Communicator<'_>,
    addresses: &mut Addresses<'_, '_>,
    dialing: &mut Dial,
    reporter: &impl Diagnostics,
    retired: IdentityRetirement,
) -> Result<(), Cause> {
    let loss = owner
        .transport_loss()
        .ok_or("UDP identity cut has no original source retirement")?;
    reporter.message(
        Severity::Info,
        "udp.identity.source-retired",
        format_args!(
            "generation={} input_bytes={} retired_operations={}",
            loss.generation,
            loss.input_bytes,
            loss.retired.len()
        ),
    );
    for operation in loss.retired {
        reporter.debug(
            "udp.identity.operation-retired",
            format_args!("{operation:?}"),
        );
    }
    addresses.transport_lost(owner)?;
    if retired.transport_was_attached {
        dialing.disconnected()?;
    }
    Ok(())
}
