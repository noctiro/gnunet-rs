//! Official clear LAN presence on the original UDP sockets. A signature check
//! yields only an address hint for the independent TRANSPORT application owner.
use gnunet_crypto::hash512;
use gnunet_types::Error;
use gnunet_udp_communicator_core::{Identity, PeerId, wire::Broadcast};
use gnunet_wire::official::nat::{Address, Endian, Profile};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};
/// Actual fixed-C IPv4 LAN discovery destination, independent of the local port.
pub const IPV4_PORT: u16 = 2086;
/// Actual fixed-C IPv6 site-local multicast group.
pub const IPV6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x13b);
/// Explicit local resource/timer policy, not a wire option.
#[derive(Clone, Copy, Debug)]
pub struct Configuration {
    /// Maximum rows in one complete supplied interface snapshot.
    pub interfaces: usize,
    /// Finite per-interface repeat interval in microseconds.
    pub interval_us: u64,
    /// Native limit of one actual socket send, captured before signing.
    pub send_lifetime: Duration,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            interfaces: 64,
            interval_us: 60_000_000,
            send_lifetime: Duration::from_secs(30),
        }
    }
}
/// One caller-owned actual interface observation, never an advertised peer hint.
/// Supply only UP, non-loopback rows from a complete successful native snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interface {
    /// Actual interface address; its port is ignored for the signature.
    pub source: SocketAddr,
    /// Actual nonzero native interface index, used for source selection/join.
    pub index: u32,
    /// Actual IPv4 broadcast (or subnet broadcast derived from the actual
    /// address/netmask on an IFF_BROADCAST interface); unused for IPv6.
    pub broadcast: Option<Ipv4Addr>,
}
impl Interface {
    pub(crate) fn validate(self) -> Result<(), Error> {
        if self.index == 0
            || self.source.ip().is_unspecified()
            || self.source.ip().is_loopback()
            || self.source.ip().is_multicast()
        {
            return Err(Error::InvalidInput);
        }
        match self.source {
            SocketAddr::V4(_) => {
                if self
                    .broadcast
                    .is_none_or(|ip| ip.is_unspecified() || ip.is_loopback() || ip.is_multicast())
                {
                    return Err(Error::InvalidInput);
                }
            }
            SocketAddr::V6(address) => {
                if address.ip().to_ipv4_mapped().is_some() || self.broadcast.is_some() {
                    return Err(Error::InvalidInput);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn target(self, local_port: u16) -> Result<SocketAddr, Error> {
        match self.source {
            SocketAddr::V4(_) => {
                Ok(SocketAddrV4::new(self.broadcast.ok_or(Error::InvalidInput)?, IPV4_PORT).into())
            }
            SocketAddr::V6(_) => {
                Ok(SocketAddrV6::new(IPV6_GROUP, local_port, 0, self.index).into())
            }
        }
    }
}
/// A verified signature bound to the actual received numeric source. This is
/// deliberately only a hint: call the original TRANSPORT application validate
/// path, never install an authenticated queue directly from this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Discovered {
    /// Signature-verified claimed public peer.
    pub peer: PeerId,
    /// Actual kernel-reported address/port, retained for TRANSPORT validation.
    pub source: SocketAddr,
    /// Caller classifier's real network category.
    pub network: u32,
}
pub(crate) struct Row {
    pub interface: Interface,
    pub due: u64,
    pub packet: Option<Broadcast>,
}
pub(crate) struct State {
    pub configuration: Configuration,
    pub rows: Vec<Row>,
    pub memberships: Vec<u32>,
    pub cursor: usize,
    pub sequence: u64,
    pub hint: Option<Discovered>,
    pub pending: [Option<(u64, SocketAddr)>; 2],
}
impl State {
    pub fn new(configuration: Configuration) -> Result<Self, Error> {
        if configuration.interfaces == 0
            || configuration.interval_us == 0
            || configuration.interval_us == u64::MAX
            || configuration.send_lifetime.is_zero()
        {
            return Err(Error::InvalidInput);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(configuration.interfaces)
            .map_err(|_| Error::Capacity)?;
        let mut memberships = Vec::new();
        memberships
            .try_reserve_exact(configuration.interfaces)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            configuration,
            rows,
            memberships,
            cursor: 0,
            sequence: 0,
            hint: None,
            pending: [None, None],
        })
    }
    pub fn update(&mut self, interfaces: &[Interface], now: u64) -> Result<(), Error> {
        if interfaces.len() > self.configuration.interfaces {
            return Err(Error::Capacity);
        }
        for (i, row) in interfaces.iter().enumerate() {
            row.validate()?;
            if interfaces[..i]
                .iter()
                .any(|prior| prior.source == row.source && prior.index == row.index)
            {
                return Err(Error::Conflict);
            }
        }
        // Allocate/check the entire replacement before altering the old rows.
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.configuration.interfaces)
            .map_err(|_| Error::Capacity)?;
        for interface in interfaces {
            let old = self.rows.iter().find(|old| old.interface == *interface);
            rows.push(Row {
                interface: *interface,
                due: old.map_or(now, |old| old.due),
                packet: old.and_then(|old| old.packet),
            });
        }
        self.rows = rows;
        self.cursor = 0;
        Ok(())
    }
    pub fn packet(&mut self, index: usize, identity: &Identity) -> Result<[u8; 96], Error> {
        let row = self.rows.get_mut(index).ok_or(Error::Stale)?;
        let packet = match row.packet {
            Some(packet) if packet.sender == identity.peer() => packet,
            _ => {
                let packet =
                    identity.broadcast(&address_hash(row.interface.source, native_profile()?)?)?;
                row.packet = Some(packet);
                packet
            }
        };
        let mut bytes = [0; 96];
        packet.encode(&mut bytes)?;
        Ok(bytes)
    }
    pub fn next_wakeup(&self, now: u64) -> Option<u64> {
        self.rows
            .iter()
            .map(|row| row.due)
            .filter(|due| *due > now && *due != u64::MAX)
            .min()
    }
}
fn endian() -> Endian {
    if cfg!(target_endian = "little") {
        Endian::Little
    } else {
        Endian::Big
    }
}
fn native_profile() -> Result<Profile, Error> {
    if cfg!(target_os = "linux") {
        Ok(Profile::linux(endian()))
    } else if cfg!(target_os = "macos") {
        Ok(Profile::darwin(endian()))
    } else if cfg!(target_os = "freebsd") {
        Ok(Profile::freebsd(endian()))
    } else {
        Err(Error::Unsupported)
    }
}

fn address_hash(address: SocketAddr, profile: Profile) -> Result<[u8; 64], Error> {
    let address = match address {
        SocketAddr::V4(address) => Address::V4 {
            ip: address.ip().octets(),
            port: 0,
        },
        SocketAddr::V6(address) => Address::V6 {
            ip: address.ip().octets(),
            port: 0,
            flow: address.flowinfo(),
            scope: address.scope_id(),
        },
    };
    let mut bytes = [0; 28];
    let size = address.encode(profile, &mut bytes)?;
    Ok(hash512(&bytes[..size]))
}
/// Parse/verify only the actual96-byte source-bound broadcast. The fixed C
/// signature hashes producer-native sockaddr bytes. Try the finite supported C
/// ABI profiles, preserving exactly the same observed source IP, flow and scope
/// and port0 in every candidate; never guess another source or scope number.
pub(crate) fn verify(
    bytes: &[u8],
    source: SocketAddr,
    local: PeerId,
) -> Result<Option<PeerId>, Error> {
    let packet = Broadcast::decode(bytes)?;
    if packet.sender == local {
        return Ok(None);
    }
    let profiles = [
        Profile::linux(Endian::Little),
        Profile::linux(Endian::Big),
        Profile::darwin(Endian::Little),
        Profile::darwin(Endian::Big),
        Profile::freebsd(Endian::Little),
        Profile::freebsd(Endian::Big),
    ];
    for profile in profiles {
        if packet.verify(&address_hash(source, profile)?).is_ok() {
            return Ok(Some(packet.sender));
        }
    }
    Err(Error::Authentication)
}
