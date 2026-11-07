//! Standard SOCKS5 no-authentication CONNECT, without swallowing HTTP/TLS bytes.
use crate::{Error, budget::Budget};
use gnunet_types::Error as Fault;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
/// Original SOCKS address, not a rewritten HTTP Host authority.
#[derive(Clone, Debug)]
pub enum Target {
    /// Exact numeric destination and requested port.
    Numeric(SocketAddr),
    /// Original UTF-8 domain bytes and requested port.
    Domain { name: String, port: u16 },
}
/// Standard failure reply code, independent of local/native completion.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Status {
    /// Actual CONNECT target was prepared.
    Granted = 0,
    /// Original local failure.
    General = 1,
    /// Explicit local policy denies this destination.
    Rules = 2,
    /// Network unavailable.
    Network = 3,
    /// No useful target address.
    Host = 4,
    /// Real connection refusal.
    Refused = 5,
    /// Original budget expired.
    Expired = 6,
    /// Unsupported command.
    Command = 7,
    /// Unsupported address type.
    Address = 8,
}
async fn read<const N: usize>(
    io: &mut (impl AsyncRead + Unpin),
    budget: &Budget,
) -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    budget.wait(io.read_exact(&mut bytes)).await??;
    Ok(bytes)
}
/// Read exactly the greeting/request. Later ClientHello or HTTP bytes remain on
/// the original stream, including when sent in one network packet.
pub async fn handshake(
    io: &mut (impl AsyncRead + AsyncWrite + Unpin),
    budget: &Budget,
) -> Result<Target, Error> {
    let hello = read::<2>(io, budget).await?;
    if hello[0] != 5 || hello[1] == 0 {
        return Err(Fault::Malformed.into());
    }
    let mut methods = [0; 255];
    budget
        .wait(io.read_exact(&mut methods[..usize::from(hello[1])]))
        .await??;
    let auth = if methods[..usize::from(hello[1])].contains(&0) {
        0
    } else {
        255
    };
    budget.wait(io.write_all(&[5, auth])).await??;
    if auth != 0 {
        return Err(Fault::PermissionDenied.into());
    }
    let request = read::<4>(io, budget).await?;
    if request[0] != 5 || request[2] != 0 {
        return Err(Fault::Malformed.into());
    }
    if request[1] != 1 {
        reply(io, Status::Command, None, budget).await?;
        return Err(Fault::Unsupported.into());
    }
    let address = match request[3] {
        1 => Some(IpAddr::V4(Ipv4Addr::from(read::<4>(io, budget).await?))),
        4 => Some(IpAddr::V6(Ipv6Addr::from(read::<16>(io, budget).await?))),
        3 => None,
        _ => {
            reply(io, Status::Address, None, budget).await?;
            return Err(Fault::Unsupported.into());
        }
    };
    let name = if address.is_none() {
        let len = usize::from(read::<1>(io, budget).await?[0]);
        if len == 0 {
            return Err(Fault::Malformed.into());
        }
        let mut bytes = [0; 255];
        budget.wait(io.read_exact(&mut bytes[..len])).await??;
        if bytes[..len].contains(&0) {
            return Err(Fault::Malformed.into());
        }
        let value = std::str::from_utf8(&bytes[..len]).map_err(|_| Fault::Malformed)?;
        if value.chars().any(char::is_control) {
            return Err(Fault::InvalidInput.into());
        }
        let mut owned = String::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(Error::Allocation)?;
        owned.push_str(value);
        Some(owned)
    } else {
        None
    };
    let port = u16::from_be_bytes(read::<2>(io, budget).await?);
    if port == 0 {
        return Err(Fault::InvalidInput.into());
    }
    Ok(match address {
        Some(ip) => Target::Numeric(SocketAddr::new(ip, port)),
        None => Target::Domain {
            name: name.ok_or(Fault::Malformed)?,
            port,
        },
    })
}
/// Write the exact standard reply using the actual local bound address when
/// CONNECT succeeded. Whole write is local exposure, not remote HTTP delivery.
pub async fn reply(
    io: &mut (impl AsyncWrite + Unpin),
    status: Status,
    bound: Option<SocketAddr>,
    budget: &Budget,
) -> Result<(), Error> {
    let mut bytes = [0; 22];
    bytes[0] = 5;
    bytes[1] = status as u8;
    let length = match bound {
        Some(SocketAddr::V6(a)) => {
            bytes[3] = 4;
            bytes[4..20].copy_from_slice(&a.ip().octets());
            bytes[20..22].copy_from_slice(&a.port().to_be_bytes());
            22
        }
        address => {
            let a = match address {
                Some(SocketAddr::V4(a)) => a,
                None => std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                Some(SocketAddr::V6(_)) => return Err(Fault::Malformed.into()),
            };
            bytes[3] = 1;
            bytes[4..8].copy_from_slice(&a.ip().octets());
            bytes[8..10].copy_from_slice(&a.port().to_be_bytes());
            10
        }
    };
    budget.wait(io.write_all(&bytes[..length])).await??;
    Ok(())
}
