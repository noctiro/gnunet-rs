//! Official v0.29.1 PILS IPC. Decoding grants no identity or key authority.
use super::{Frame, MessageHeader, MessageType, SignaturePurpose, message_type as mt};
use gnunet_types::Error;

/// Bytes before the HELLO block in a peer update.
pub const PEER_UPDATE_PREFIX: usize = 72;
/// Fixed KEM/ECDH request and KEM result length.
pub const KEY_MESSAGE_LEN: usize = 40;
/// Fixed ECDH result length.
pub const ECDH_RESULT_LEN: usize = 72;
/// Fixed signature result length.
pub const SIGN_RESULT_LEN: usize = 104;

/// Complete standard SIGN request extent for a purpose region. This checks
/// the same nonempty payload and16-bit envelope used by normal serialization.
pub fn sign_request_len(region_bytes: usize) -> Result<usize, Error> {
    if region_bytes <= 8 {
        return Err(Error::InvalidInput);
    }
    length(8, region_bytes)
}

/// Public peer update; the HELLO, hash and derived public key require verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerUpdate<'a> {
    /// Announced address hash, not the hash of the public identity.
    pub hash: [u8; 64],
    /// Exact raw HELLO block.
    pub block: &'a [u8],
}
impl<'a> PeerUpdate<'a> {
    /// Decode one exact current peer update.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if Frame::decode(bytes)?.header().message_type() != mt::PILS_PEER_ID {
            return Err(Error::Unsupported);
        }
        let block = block(bytes, PEER_UPDATE_PREFIX, 68)?;
        Ok(Self {
            hash: fixed(bytes, 4)?,
            block,
        })
    }
    /// Encode atomically, including the exact raw block length.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = length(PEER_UPDATE_PREFIX, self.block.len())?;
        let b = prepare(mt::PILS_PEER_ID, n, out)?;
        b[4..68].copy_from_slice(&self.hash);
        b[68..72].copy_from_slice(&(self.block.len() as u32).to_be_bytes());
        b[72..n].copy_from_slice(self.block);
        Ok(n)
    }
}

/// One public client request. Request numbers are connection-local.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Replace the current context using an unsigned raw HELLO address block.
    Feed {
        /// Raw HELLO block; its claimed peer/signature are not authority.
        block: &'a [u8],
    },
    /// Sign the exact GNUnet purpose region, without hashing it first.
    Sign {
        /// Original connection-local request number.
        request: u32,
        /// Complete size/purpose header and signed bytes.
        region: &'a [u8],
    },
    /// Decapsulate the official X25519 DHKEM encapsulation.
    Decapsulate {
        /// Original request number.
        request: u32,
        /// Raw Montgomery coordinate.
        encapsulation: [u8; 32],
    },
    /// Return the legacy SHA512(X25519) key material.
    Ecdh {
        /// Original request number.
        request: u32,
        /// Raw Montgomery public key.
        public: [u8; 32],
    },
}
impl<'a> Request<'a> {
    /// Decode one exact request, rejecting inconsistent purpose lengths safely.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        match Frame::decode(bytes)?.header().message_type() {
            mt::PILS_FEED_ADDRESSES => Ok(Self::Feed {
                block: block(bytes, 8, 4)?,
            }),
            mt::PILS_SIGN_REQUEST => {
                let region = bytes.get(8..).ok_or(Error::Truncated)?;
                check_region(region)?;
                Ok(Self::Sign {
                    request: number(bytes, 4)?,
                    region,
                })
            }
            mt::PILS_KEM_DECAPS => {
                exact(bytes, KEY_MESSAGE_LEN)?;
                Ok(Self::Decapsulate {
                    request: number(bytes, 36)?,
                    encapsulation: fixed(bytes, 4)?,
                })
            }
            mt::PILS_ECDH => {
                exact(bytes, KEY_MESSAGE_LEN)?;
                Ok(Self::Ecdh {
                    request: number(bytes, 36)?,
                    public: fixed(bytes, 4)?,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Encode one complete frame; failed preflight preserves the whole output.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let (kind, n) = match self {
            Self::Feed { block } => (mt::PILS_FEED_ADDRESSES, length(8, block.len())?),
            Self::Sign { region, .. } => {
                check_region(region)?;
                (mt::PILS_SIGN_REQUEST, sign_request_len(region.len())?)
            }
            Self::Decapsulate { .. } => (mt::PILS_KEM_DECAPS, KEY_MESSAGE_LEN),
            Self::Ecdh { .. } => (mt::PILS_ECDH, KEY_MESSAGE_LEN),
        };
        let b = prepare(kind, n, out)?;
        match self {
            Self::Feed { block } => {
                b[4..8].copy_from_slice(&(block.len() as u32).to_be_bytes());
                b[8..n].copy_from_slice(block);
            }
            Self::Sign { request, region } => {
                b[4..8].copy_from_slice(&request.to_be_bytes());
                b[8..n].copy_from_slice(region);
            }
            Self::Decapsulate {
                request,
                encapsulation,
            } => {
                b[4..36].copy_from_slice(&encapsulation);
                b[36..40].copy_from_slice(&request.to_be_bytes());
            }
            Self::Ecdh { request, public } => {
                b[4..36].copy_from_slice(&public);
                b[36..40].copy_from_slice(&request.to_be_bytes());
            }
        }
        Ok(n)
    }
}

/// A server response. Key material borrows the original secret frame buffer;
/// callers must erase retained buffers when released. No Debug/Clone is provided.
pub enum Response<'a> {
    /// Public context announcement.
    PeerUpdate(PeerUpdate<'a>),
    /// Signature and the identity that actually signed it.
    Signature {
        /// Original request number.
        request: u32,
        /// Public peer identity.
        peer: [u8; 32],
        /// Exact Ed25519 signature, zero on reference crypto failure.
        signature: [u8; 64],
    },
    /// Official DHKEM secret, zero on reference crypto failure.
    Decapsulation {
        /// Original request number.
        request: u32,
        /// Borrowed secret bytes.
        key: &'a [u8; 32],
    },
    /// Legacy hashed DH material, zero on reference crypto failure.
    Ecdh {
        /// Original request number.
        request: u32,
        /// Borrowed secret bytes.
        key: &'a [u8; 64],
    },
}
impl<'a> Response<'a> {
    /// Decode one response. A structurally valid zero result is not crypto success.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        match Frame::decode(bytes)?.header().message_type() {
            mt::PILS_PEER_ID => Ok(Self::PeerUpdate(PeerUpdate::decode(bytes)?)),
            mt::PILS_SIGN_RESULT => {
                exact(bytes, SIGN_RESULT_LEN)?;
                Ok(Self::Signature {
                    request: number(bytes, 100)?,
                    peer: fixed(bytes, 4)?,
                    signature: fixed(bytes, 36)?,
                })
            }
            mt::PILS_DECAPS_RESULT => {
                exact(bytes, KEY_MESSAGE_LEN)?;
                Ok(Self::Decapsulation {
                    request: number(bytes, 36)?,
                    key: bytes[4..36].try_into().map_err(|_| Error::Malformed)?,
                })
            }
            mt::PILS_ECDH_RESULT => {
                exact(bytes, ECDH_RESULT_LEN)?;
                Ok(Self::Ecdh {
                    request: number(bytes, 68)?,
                    key: bytes[4..68].try_into().map_err(|_| Error::Malformed)?,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Encode into caller-owned storage; key bytes remain the caller's secret data.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let (kind, n) = match self {
            Self::PeerUpdate(update) => return update.encode(out),
            Self::Signature { .. } => (mt::PILS_SIGN_RESULT, SIGN_RESULT_LEN),
            Self::Decapsulation { .. } => (mt::PILS_DECAPS_RESULT, KEY_MESSAGE_LEN),
            Self::Ecdh { .. } => (mt::PILS_ECDH_RESULT, ECDH_RESULT_LEN),
        };
        let b = prepare(kind, n, out)?;
        match self {
            Self::Signature {
                request,
                peer,
                signature,
            } => {
                b[4..36].copy_from_slice(&peer);
                b[36..100].copy_from_slice(&signature);
                b[100..104].copy_from_slice(&request.to_be_bytes());
            }
            Self::Decapsulation { request, key } => {
                b[4..36].copy_from_slice(key);
                b[36..40].copy_from_slice(&request.to_be_bytes());
            }
            Self::Ecdh { request, key } => {
                b[4..68].copy_from_slice(key);
                b[68..72].copy_from_slice(&request.to_be_bytes());
            }
            Self::PeerUpdate(_) => return Err(Error::InvalidInput),
        }
        Ok(n)
    }
}
fn exact(bytes: &[u8], n: usize) -> Result<(), Error> {
    if bytes.len() == n {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}
fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    bytes
        .get(offset..offset + N)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn number(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(fixed(bytes, offset)?))
}
fn block(bytes: &[u8], prefix: usize, offset: usize) -> Result<&[u8], Error> {
    let b = bytes.get(prefix..).ok_or(Error::Truncated)?;
    if number(bytes, offset)? as usize != b.len() {
        return Err(Error::Malformed);
    }
    Ok(b)
}
fn length(prefix: usize, payload: usize) -> Result<usize, Error> {
    let n = prefix.checked_add(payload).ok_or(Error::Overflow)?;
    MessageHeader::from_total_size(mt::PILS_PEER_ID, n)?;
    Ok(n)
}
fn prepare(kind: MessageType, n: usize, out: &mut [u8]) -> Result<&mut [u8], Error> {
    let header = MessageHeader::from_total_size(kind, n)?;
    if out.len() < n {
        return Err(Error::Capacity);
    }
    header.encode(out)?;
    Ok(&mut out[..n])
}
fn check_region(region: &[u8]) -> Result<(), Error> {
    let purpose = SignaturePurpose::decode(region.get(..8).ok_or(Error::Truncated)?)?;
    purpose.validate_signed_size(region.len())
}
