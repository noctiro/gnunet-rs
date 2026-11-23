//! Direct DNS-body reply encoding; all size refusals precede output mutation.
use super::{Family, ReplyTuple, helper};
use gnunet_types::Error;
use gnunet_vpn::packet::{self, UDP};
use gnunet_wire::official::{MessageHeader, message_type};

/// Actual framing accepted by the selected original native or helper source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Framing {
    /// Raw real IP/UDP reply, without any helper or native device prefix.
    Raw,
    /// Official MQ4/TUN_PI4 followed by the real IP/UDP reply.
    Helper,
}
impl Framing {
    const fn prefix(self) -> usize {
        match self {
            Self::Raw => 0,
            Self::Helper => helper::HELPER_PREFIX,
        }
    }
}

impl ReplyTuple {
    /// Complete output size for a DNS body, including actual selected framing.
    ///
    /// # Errors
    /// Refuses overflow, IP/UDP length overflow and a complete helper frame
    /// exceeding 65535 bytes. The DNS engine's IPC bound is independent.
    pub fn encoded_len(&self, dns_bytes: usize, framing: Framing) -> Result<usize, Error> {
        let udp = dns_bytes.checked_add(8).ok_or(Error::Overflow)?;
        if udp > usize::from(u16::MAX) {
            return Err(Error::TooLarge);
        }
        let header = match self.source.family() {
            Family::V4 => 20,
            Family::V6 => 40,
        };
        let raw = udp.checked_add(header).ok_or(Error::Overflow)?;
        if self.source.family() == Family::V4 && raw > usize::from(u16::MAX) {
            return Err(Error::TooLarge);
        }
        let total = framing.prefix().checked_add(raw).ok_or(Error::Overflow)?;
        if matches!(framing, Framing::Helper) && total > usize::from(u16::MAX) {
            return Err(Error::TooLarge);
        }
        Ok(total)
    }

    /// Encode the reversed original tuple with real IP/UDP checksums.
    /// The DNS body is copied directly into its final frame exactly once.
    ///
    /// # Errors
    /// Size and output-capacity refusals leave every output byte unchanged.
    pub fn encode(&self, dns: &[u8], framing: Framing, out: &mut [u8]) -> Result<usize, Error> {
        let total = self.encoded_len(dns.len(), framing)?;
        if out.len() < total {
            return Err(Error::Capacity);
        }
        let helper = match framing {
            Framing::Raw => None,
            Framing::Helper => Some(MessageHeader::from_total_size(
                message_type::DNS_HELPER,
                total,
            )?),
        };
        let prefix = framing.prefix();
        let mut udp = [0; 8];
        udp[..2].copy_from_slice(&self.destination_port.to_be_bytes());
        udp[2..4].copy_from_slice(&self.source_port.to_be_bytes());
        // The checked tuple fixes equal families and UDP skeleton/lengths;
        // encoded_len preflights every fallible builder condition.
        packet::build_parts(
            self.destination,
            self.source,
            UDP,
            &udp,
            dns,
            &mut out[prefix..total],
        )?;
        if let Some(header) = helper {
            header.encode(out)?;
            out[4..6].fill(0);
            out[6..prefix].copy_from_slice(&helper::protocol(self.source.family()).to_be_bytes());
        }
        Ok(total)
    }
}
