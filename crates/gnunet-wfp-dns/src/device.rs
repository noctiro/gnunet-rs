//! Local buffered Windows device records for DNS capture and reply.
//! These records stay between the driver and its service.
use crate::RequestId;
use core::num::NonZeroU64;

pub mod maintenance;

/// Canonical user-mode path of the device.
pub const PATH: &str = r"\\.\GNUnetDnsIntercept";
/// Buffered query for the original native write disposition.
pub const IOCTL_COMPLETION: u32 = 0x0022_6000;
/// Buffered publication of an unnamed service wake event.
pub const IOCTL_SET_EVENT: u32 = 0x0022_6004;
/// Start capture with the original upstream UDP socket descriptors.
pub const IOCTL_START: u32 = 0x0022_e008;
/// Revoke capture and release the driver-side upstream handle owners.
pub const IOCTL_STOP: u32 = 0x0022_e00c;
/// Maximum number of original upstream sockets in one device session.
pub const MAX_UPSTREAM_SOCKETS: usize = 16;
/// Bytes occupied by one socket handle and its native endpoint identity.
pub const UPSTREAM_BYTES: usize = 2 * size_of::<u64>();
/// Size of one completion record (token, native status, and gate verdict).
pub const COMPLETION_BYTES: usize = TOKEN_BYTES + size_of::<i32>() + 1;

/// Number of bytes in a local opaque request token.
pub const TOKEN_BYTES: usize = size_of::<u64>();
/// Maximum DNS body in a UDP datagram with a 16-bit length.
pub const MAX_DNS_BYTES: usize = u16::MAX as usize - 8;
/// Maximum required buffer for a complete local DNS record.
pub const MAX_RECORD_BYTES: usize = TOKEN_BYTES + MAX_DNS_BYTES;
const DNS_HEADER_BYTES: usize = 12;

/// Local record could not be encoded or decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Missing or zero request token.
    Token,
    /// Missing DNS header or oversized DNS message.
    Length,
    /// The DNS QR bit disagrees with the expected device command.
    Direction,
    /// The caller supplied insufficient output capacity.
    Capacity,
    /// A START socket or ALE endpoint identity was zero or duplicated.
    Upstream,
    /// The completion contained an invalid gate verdict.
    Verdict,
}

/// An authenticated service's original IFS socket and observed ALE endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Upstream {
    /// Original caller-process SOCKET value. The kernel checks its native type.
    pub socket: NonZeroU64,
    /// Observed WFP transport endpoint identity of that same original socket.
    pub endpoint: NonZeroU64,
}

impl Upstream {
    /// Encode one fixed-size local device record.
    pub fn encode(self) -> [u8; UPSTREAM_BYTES] {
        let mut out = [0; UPSTREAM_BYTES];
        out[..TOKEN_BYTES].copy_from_slice(&self.socket.get().to_le_bytes());
        out[TOKEN_BYTES..].copy_from_slice(&self.endpoint.get().to_le_bytes());
        out
    }

    /// Decode an exact local descriptor.
    ///
    /// # Errors
    /// Refuses zero handles or endpoint identities and invalid extents.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != UPSTREAM_BYTES {
            return Err(Error::Length);
        }
        let (socket, endpoint) = input
            .split_first_chunk::<TOKEN_BYTES>()
            .ok_or(Error::Upstream)?;
        let endpoint = endpoint
            .first_chunk::<TOKEN_BYTES>()
            .ok_or(Error::Upstream)?;
        Ok(Self {
            socket: NonZeroU64::new(u64::from_le_bytes(*socket)).ok_or(Error::Upstream)?,
            endpoint: NonZeroU64::new(u64::from_le_bytes(*endpoint)).ok_or(Error::Upstream)?,
        })
    }
}

/// One nonempty START list with distinct socket and ALE endpoint identities.
#[derive(Debug)]
pub struct Upstreams {
    entries: [Upstream; MAX_UPSTREAM_SOCKETS],
    len: usize,
}

impl Upstreams {
    /// Start a list with one original socket.
    #[must_use]
    pub const fn new(first: Upstream) -> Self {
        Self {
            entries: [first; MAX_UPSTREAM_SOCKETS],
            len: 1,
        }
    }

    /// Decode and validate the whole START record before native acquisition.
    ///
    /// # Errors
    /// Refuses invalid extents, zero identities and duplicate identities.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let (entries, remainder) = input.as_chunks::<UPSTREAM_BYTES>();
        if entries.len() > MAX_UPSTREAM_SOCKETS || !remainder.is_empty() {
            return Err(Error::Length);
        }
        let (first, rest) = entries.split_first().ok_or(Error::Length)?;
        let mut list = Self::new(Upstream::decode(first)?);
        for entry in rest {
            list.push(Upstream::decode(entry)?)?;
        }
        Ok(list)
    }

    /// Append an original socket in wire order.
    ///
    /// # Errors
    /// Refuses a full list or a repeated socket or endpoint identity.
    pub fn push(&mut self, next: Upstream) -> Result<(), Error> {
        if self
            .as_slice()
            .iter()
            .any(|entry| entry.socket == next.socket || entry.endpoint == next.endpoint)
        {
            return Err(Error::Upstream);
        }
        let slot = self.entries.get_mut(self.len).ok_or(Error::Length)?;
        *slot = next;
        self.len += 1;
        Ok(())
    }

    /// Exactly the validated entries, in their original order.
    #[must_use]
    pub fn as_slice(&self) -> &[Upstream] {
        &self.entries[..self.len]
    }
}

/// One local reply command. Only the driver can authorize its token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reply<'a> {
    /// Discard an original capture without submitting a reply.
    Discard(RequestId),
    /// Submit DNS response bytes using the original kernel-owned path.
    Datagram(RequestId, &'a [u8]),
}

/// Decode one dequeued query, borrowing the original local record.
///
/// # Errors
/// Rejects an invalid token, DNS body length or response where a query is expected.
pub fn query(record: &[u8]) -> Result<(RequestId, &[u8]), Error> {
    let (request, dns) = split(record)?;
    check_dns(dns, false)?;
    Ok((request, dns))
}

/// Decode one original service reply. A token-only record discards the capture.
///
/// # Errors
/// Rejects an invalid token, DNS body length or query where a reply is expected.
pub fn reply(record: &[u8]) -> Result<Reply<'_>, Error> {
    let (request, dns) = split(record)?;
    if dns.is_empty() {
        return Ok(Reply::Discard(request));
    }
    check_dns(dns, true)?;
    Ok(Reply::Datagram(request, dns))
}

/// Encode a local query or reply token followed by the whole DNS body.
///
/// # Errors
/// Rejects an oversized body or insufficient output space.
pub fn encode(request: RequestId, dns: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if dns.len() > MAX_DNS_BYTES {
        return Err(Error::Length);
    }
    let size = TOKEN_BYTES + dns.len();
    let out = out.get_mut(..size).ok_or(Error::Capacity)?;
    let (token, payload) = out.split_at_mut(TOKEN_BYTES);
    token.copy_from_slice(&request.context().get().to_le_bytes());
    payload.copy_from_slice(dns);
    Ok(size)
}

/// Original native status and independent receive-gate observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    /// Original issued request token.
    pub request: RequestId,
    /// Native status returned by the completion.
    pub status: i32,
    /// The receive gate authorized this original before completion.
    pub authorized: bool,
}

/// Decode one exact local completion record.
///
/// # Errors
/// Refuses an invalid token, extent, or receive-gate observation.
pub fn decode_completion(record: &[u8]) -> Result<Completion, Error> {
    let (request, body) = split(record)?;
    let [s0, s1, s2, s3, authorized] = *body else {
        return Err(Error::Length);
    };
    let authorized = match authorized {
        0 => false,
        1 => true,
        _ => return Err(Error::Verdict),
    };
    Ok(Completion {
        request,
        status: i32::from_le_bytes([s0, s1, s2, s3]),
        authorized,
    })
}

/// Encode one original native completion in little-endian format.
pub fn encode_completion(
    request: RequestId,
    status: i32,
    authorized: bool,
) -> [u8; COMPLETION_BYTES] {
    let mut out = [0; COMPLETION_BYTES];
    out[..TOKEN_BYTES].copy_from_slice(&request.context().get().to_le_bytes());
    out[TOKEN_BYTES..COMPLETION_BYTES - 1].copy_from_slice(&status.to_le_bytes());
    out[COMPLETION_BYTES - 1] = u8::from(authorized);
    out
}

fn split(record: &[u8]) -> Result<(RequestId, &[u8]), Error> {
    let (token, dns) = record
        .split_first_chunk::<TOKEN_BYTES>()
        .ok_or(Error::Token)?;
    let context = NonZeroU64::new(u64::from_le_bytes(*token)).ok_or(Error::Token)?;
    Ok((RequestId::from_context(context), dns))
}

fn check_dns(dns: &[u8], response: bool) -> Result<(), Error> {
    if !(DNS_HEADER_BYTES..=MAX_DNS_BYTES).contains(&dns.len()) {
        return Err(Error::Length);
    }
    if (dns[2] & 0x80 != 0) != response {
        return Err(Error::Direction);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_decoder_validates_distinct_originals_before_acquisition() {
        let first = Upstream {
            socket: NonZeroU64::MIN,
            endpoint: NonZeroU64::MIN.saturating_add(1),
        };
        let second = Upstream {
            socket: first.endpoint,
            endpoint: first.socket,
        };
        let mut input = [0; 2 * UPSTREAM_BYTES];
        input[..UPSTREAM_BYTES].copy_from_slice(&first.encode());
        input[UPSTREAM_BYTES..].copy_from_slice(&second.encode());
        assert!(matches!(
            Upstreams::decode(&input),
            Ok(list) if list.as_slice() == [first, second]
        ));
        assert_eq!(Upstreams::decode(&[]).err(), Some(Error::Length));
        assert_eq!(
            Upstreams::decode(&input[..input.len() - 1]).err(),
            Some(Error::Length)
        );
        for duplicate in [
            Upstream {
                socket: first.socket,
                ..second
            },
            Upstream {
                endpoint: first.endpoint,
                ..second
            },
        ] {
            input[UPSTREAM_BYTES..].copy_from_slice(&duplicate.encode());
            assert_eq!(Upstreams::decode(&input).err(), Some(Error::Upstream));
        }
    }
}
