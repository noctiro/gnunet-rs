//! Native framing only; IP checksum/transport policy belongs to the packet core.
use std::fmt;
/// Complete raw IP version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}
/// Actual native framing selected by device verification, never guessed from data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Linux IFF_NO_PI.
    RawIp,
    /// Linux tun_pi: native flags (only zero accepted), network ethertype.
    LinuxPi,
    /// Darwin utun: network u32 AF_INET=2 or AF_INET6=30.
    Utun,
}
impl Mode {
    /// Actual per-packet prefix size.
    #[must_use]
    pub const fn prefix_len(self) -> usize {
        match self {
            Self::RawIp => 0,
            _ => 4,
        }
    }
}
/// Rejected actual packet structure; this never claims checksum verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    /// Incomplete IP or native header.
    Truncated,
    /// Unsupported version or native protocol field.
    Unsupported,
    /// Header-declared length differs from the complete packet.
    Length,
    /// Native protocol prefix disagrees with the IP version.
    Family,
    /// Unsupported/nonzero actual Linux PI flags (including truncation).
    PiFlags([u8; 2]),
    /// Explicit per-packet capacity exceeded.
    TooLarge,
}
impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TUN packet: {self:?}")
    }
}
impl std::error::Error for PacketError {}
/// Check complete IP length/version only. No checksum or peer authority is inferred.
pub fn version(raw: &[u8]) -> Result<Version, PacketError> {
    let first = *raw.first().ok_or(PacketError::Truncated)?;
    match first >> 4 {
        4 => {
            if raw.len() < 20 {
                return Err(PacketError::Truncated);
            }
            let header = usize::from(first & 15) * 4;
            if header < 20 || header > raw.len() {
                return Err(PacketError::Length);
            }
            let n = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
            if n != raw.len() || n < header {
                return Err(PacketError::Length);
            }
            Ok(Version::V4)
        }
        6 => {
            if raw.len() < 40 {
                return Err(PacketError::Truncated);
            }
            let n = 40 + usize::from(u16::from_be_bytes([raw[4], raw[5]]));
            if n != raw.len() {
                return Err(PacketError::Length);
            }
            Ok(Version::V6)
        }
        _ => Err(PacketError::Unsupported),
    }
}
/// Decode actual native framing into one complete raw IP slice.
pub fn decode(mode: Mode, frame: &[u8]) -> Result<(Version, &[u8]), PacketError> {
    let raw = frame
        .get(mode.prefix_len()..)
        .ok_or(PacketError::Truncated)?;
    let v = version(raw)?;
    match mode {
        Mode::RawIp => {}
        Mode::LinuxPi => {
            if frame[..2] != [0, 0] {
                return Err(PacketError::PiFlags([frame[0], frame[1]]));
            }
            let p = u16::from_be_bytes([frame[2], frame[3]]);
            if p != match v {
                Version::V4 => 0x0800,
                Version::V6 => 0x86dd,
            } {
                return Err(PacketError::Family);
            }
        }
        Mode::Utun => {
            let p = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
            if p != match v {
                Version::V4 => 2,
                Version::V6 => 30,
            } {
                return Err(PacketError::Family);
            }
        }
    }
    Ok((v, raw))
}
/// Prefix for a validated complete IP packet. Only prefix_len bytes are used.
#[must_use]
pub const fn prefix(mode: Mode, v: Version) -> [u8; 4] {
    match mode {
        Mode::RawIp => [0; 4],
        Mode::LinuxPi => match v {
            Version::V4 => [0, 0, 8, 0],
            Version::V6 => [0, 0, 0x86, 0xdd],
        },
        Mode::Utun => match v {
            Version::V4 => [0, 0, 0, 2],
            Version::V6 => [0, 0, 0, 30],
        },
    }
}
