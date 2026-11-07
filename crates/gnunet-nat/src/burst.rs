//! Public util NAT datagrams. These contain no authentication or message header.
use gnunet_types::Error;
pub use gnunet_wire::official::nat::Endian;

/// Exact packed public BurstSync length.
pub const SYNC_BYTES: usize = 12;
/// Exact packed public BurstMessage length.
pub const MESSAGE_BYTES: usize = 36;

/// RTT synchronization proposal, preserving the producer's native enum value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BurstSync {
    /// Average RTT in microseconds. `u64::MAX` means forever and is never ready.
    pub rtt_micros: u64,
    /// Native `GNUNET_GenericReturnValue`; precisely 1 selects the shorter delay.
    pub ready: i32,
}
impl BurstSync {
    /// Decode an exact public structure using the explicit producer byte order.
    pub fn decode(input: &[u8], producer: Endian) -> Result<Self, Error> {
        if input.len() != SYNC_BYTES {
            return Err(Error::Malformed);
        }
        let mut rtt = [0; 8];
        rtt.copy_from_slice(&input[..8]);
        let mut ready = [0; 4];
        ready.copy_from_slice(&input[8..]);
        Ok(Self {
            rtt_micros: u64::from_be_bytes(rtt),
            ready: producer.u32(ready) as i32,
        })
    }
    /// Encode without a GNUnet header, padding, ACK, or canonicalized enum.
    pub fn encode(self, producer: Endian, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < SYNC_BYTES {
            return Err(Error::Capacity);
        }
        out[..8].copy_from_slice(&self.rtt_micros.to_be_bytes());
        out[8..12].copy_from_slice(&producer.put32(self.ready as u32));
        Ok(SYNC_BYTES)
    }
    /// Official readiness rule, including strict 150ms difference and finite RTTs.
    /// A saturated delay is preserved here; the native owner rejects a delay that
    /// cannot fit its original finite lifetime.
    pub fn delay(self, local_rtt_micros: u64) -> Option<u64> {
        if self.rtt_micros == u64::MAX
            || local_rtt_micros == u64::MAX
            || self.rtt_micros.abs_diff(local_rtt_micros) >= 150_000
        {
            return None;
        }
        Some(local_rtt_micros.saturating_mul(if self.ready == 1 { 2 } else { 4 }))
    }
}

/// An unauthenticated probe. The public peer bytes are an assertion by the sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BurstMessage {
    /// Initialized public identity bytes; zero is also a valid raw wire value.
    pub peer: [u8; 32],
    /// Producer-native unsigned int, preserved even if outside the UDP port range.
    pub local_port: u32,
}
impl BurstMessage {
    /// Produce the complete initialized public datagram without allocation.
    pub fn to_bytes(self, producer: Endian) -> [u8; MESSAGE_BYTES] {
        let mut bytes = [0; MESSAGE_BYTES];
        bytes[..32].copy_from_slice(&self.peer);
        bytes[32..].copy_from_slice(&producer.put32(self.local_port));
        bytes
    }
    /// Decode only an exact 36-byte datagram, never a truncated prefix.
    pub fn decode(input: &[u8], producer: Endian) -> Result<Self, Error> {
        if input.len() != MESSAGE_BYTES {
            return Err(Error::Malformed);
        }
        let mut peer = [0; 32];
        peer.copy_from_slice(&input[..32]);
        let mut port = [0; 4];
        port.copy_from_slice(&input[32..]);
        Ok(Self {
            peer,
            local_port: producer.u32(port),
        })
    }
    /// Encode initialized bytes. No field establishes peer authentication.
    pub fn encode(self, producer: Endian, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < MESSAGE_BYTES {
            return Err(Error::Capacity);
        }
        out[..MESSAGE_BYTES].copy_from_slice(&self.to_bytes(producer));
        Ok(MESSAGE_BYTES)
    }
}
