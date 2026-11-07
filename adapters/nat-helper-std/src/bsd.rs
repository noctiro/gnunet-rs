//! Darwin and FreeBSD12+ raw IPv4 ABI adaptation (source-qualified, not executed).
//! The native adapter restores only fields changed by the actual raw kernel ABI,
//! including XNU's TIMXCEED quoted-length conversion. Packet/checksum validation
//! stays in gnunet-nat; no private framing or checksum repair is added.
use gnunet_nat::icmp::{self, IpLengthProfile, Observation};
use gnunet_types::Error;
#[cfg(target_os = "freebsd")]
pub(crate) const PROFILE: IpLengthProfile = IpLengthProfile::Network;
#[cfg(all(target_os = "macos", target_endian = "little"))]
pub(crate) const PROFILE: IpLengthProfile =
    IpLengthProfile::Native(gnunet_wire::official::nat::Endian::Little);
#[cfg(all(target_os = "macos", target_endian = "big"))]
pub(crate) const PROFILE: IpLengthProfile =
    IpLengthProfile::Native(gnunet_wire::official::nat::Endian::Big);
pub(crate) fn observe(packet: &mut [u8]) -> Result<Option<Observation>, Error> {
    // This native helper only validates/normalizes borrowed bytes; no syscall is
    // involved. Structurally invalid raw input is discarded, like other packets.
    gnunet_native::nat_helper::normalize_received(packet).map_err(|_| Error::Malformed)?;
    icmp::observe(packet)
}
