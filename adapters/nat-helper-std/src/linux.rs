//! Linux raw IPv4 lengths/offsets are already in network order.
use gnunet_nat::icmp::{self, IpLengthProfile, Observation};
use gnunet_types::Error;
pub(crate) const PROFILE: IpLengthProfile = IpLengthProfile::Network;
pub(crate) fn observe(packet: &mut [u8]) -> Result<Option<Observation>, Error> {
    icmp::observe(packet)
}
