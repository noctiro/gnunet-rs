//! Bounded explicit entropy for real source IP/port choice; no global counter.
use crate::{
    Address, Family,
    policy::{Endpoint, Prefix, Protocol},
};
use gnunet_types::Error;
/// Caller-provided actual fresh entropy. Failure must not create an address.
pub trait Entropy {
    /// Fill the complete requested bytes or return the real refusal.
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error>;
}
/// Configured actual TUN source subnet. The native host must really provision it.
#[derive(Clone, Copy, Debug)]
pub struct Pool {
    /// Actual configured local interface address and subnet width.
    pub subnet: Prefix,
}
impl Pool {
    /// Validate the caller's selected real subnet.
    pub fn validate(self) -> Result<(), Error> {
        self.subnet.validate()
    }
    /// Actual source family.
    #[must_use]
    pub const fn family(self) -> Family {
        self.subnet.address.family()
    }
    /// Select one candidate. Tuple uniqueness is separately checked against all
    /// live and quarantined flow records before committing the candidate.
    pub fn candidate(
        self,
        protocol: Protocol,
        requested_port: u16,
        entropy: &mut impl Entropy,
        draws: u16,
    ) -> Result<Endpoint, Error> {
        self.validate()?;
        if draws == 0 {
            return Err(Error::Capacity);
        }
        let address = match self.subnet.address {
            Address::V4(interface) => {
                Address::V4(sample(interface, self.subnet.bits, entropy, draws)?)
            }
            Address::V6(interface) => {
                Address::V6(sample(interface, self.subnet.bits, entropy, draws)?)
            }
        };
        let port = if protocol.is_icmp() {
            0
        } else if requested_port != 0 {
            requested_port
        } else {
            let mut selected = None;
            for _ in 0..draws {
                let mut b = [0; 4];
                entropy.fill(&mut b)?;
                let n = u32::from_be_bytes(b);
                let limit = u32::MAX - (u32::MAX % 28232);
                if n < limit {
                    selected = Some(32768 + (n % 28232) as u16);
                    break;
                }
            }
            selected.ok_or(Error::EntropyUnavailable)?
        };
        Ok(Endpoint { address, port })
    }
}
fn sample<const N: usize>(
    interface: [u8; N],
    prefix: u8,
    entropy: &mut impl Entropy,
    draws: u16,
) -> Result<[u8; N], Error> {
    let width = N * 8;
    if usize::from(prefix) > width {
        return Err(Error::InvalidInput);
    }
    // Single-address/point-to-point pools retain the reference's explicit
    // interface-address case, avoiding an impossible unbounded rejection loop.
    if usize::from(prefix) >= width - 1 {
        return Ok(interface);
    }
    let mut network = interface;
    let mut last = interface;
    for i in 0..N {
        let fixed = usize::from(prefix).saturating_sub(i * 8).min(8);
        let mask = if fixed == 0 { 0 } else { 0xffu8 << (8 - fixed) };
        network[i] &= mask;
        last[i] |= !mask;
    }
    for _ in 0..draws {
        let mut bytes = [0; N];
        entropy.fill(&mut bytes)?;
        for i in 0..N {
            let fixed = usize::from(prefix).saturating_sub(i * 8).min(8);
            let mask = if fixed == 0 { 0 } else { 0xffu8 << (8 - fixed) };
            bytes[i] = (network[i] & mask) | (bytes[i] & !mask);
        }
        if bytes != interface && bytes != last && bytes != network {
            return Ok(bytes);
        }
    }
    Err(Error::EntropyUnavailable)
}
