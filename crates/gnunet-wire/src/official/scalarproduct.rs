//! Official scalarproduct IPC and ECC/Paillier CADET frames, GNUnet v0.29.1.
//!
//! This module borrows exact packed element, point and ciphertext extents. It
//! does not validate keys/points, decrypt a product, admit a session, or infer
//! success from a local write. The original owner supplies role, multipart
//! totals, intersection cardinality and cryptographic validation.
//!
//! The fixed C implementation sends TWO ECC points per Alice vector entry,
//! despite the shorter array comment in its header. Paillier Bob replies carry
//! two base ciphertexts followed by two ciphertext columns per contained entry;
//! multipart replies omit those base values. Original column order is retained.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;

/// Hash/session/key size in the official public API.
pub const HASH_BYTES: usize = 64;
/// Public peer identity size.
pub const PEER_BYTES: usize = 32;
/// One hash key and one signed big-endian i64.
pub const ELEMENT_BYTES: usize = HASH_BYTES + 8;
/// One compact GNUnet Curve25519/Ed25519 point. Bytes alone prove no valid point.
pub const POINT_BYTES: usize = 32;
/// Fixed 2048-bit Paillier public modulus size.
pub const PAILLIER_KEY_BYTES: usize = 256;
/// NBO remaining-operations i32 followed by 4096 ciphertext bits.
pub const CIPHERTEXT_BYTES: usize = 4 + 512;

fn fixed(input: &[u8], size: usize) -> Result<(), Error> {
    if input.len() < size {
        Err(Error::Truncated)
    } else if input.len() != size {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}
fn array<const N: usize>(input: &[u8], at: usize) -> Result<&[u8; N], Error> {
    input
        .get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Malformed)
}
fn number(input: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(*array(input, at)?))
}
fn list<const N: usize>(input: &[u8], start: usize) -> Result<&[[u8; N]], Error> {
    let (values, trailing) = input.get(start..).ok_or(Error::Truncated)?.as_chunks::<N>();
    if !trailing.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(values)
}
fn count(actual: usize, declared: u32, factor: usize, extra: usize) -> Result<(), Error> {
    let required = usize::try_from(declared)
        .map_err(|_| Error::TooLarge)?
        .checked_mul(factor)
        .and_then(|n| n.checked_add(extra))
        .ok_or(Error::Overflow)?;
    if actual != required {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn extent(kind: MessageType, prefix: usize, stride: usize, n: usize) -> Result<usize, Error> {
    let len = n
        .checked_mul(stride)
        .and_then(|n| n.checked_add(prefix))
        .ok_or(Error::Overflow)?;
    MessageHeader::from_total_size(kind, len)?;
    Ok(len)
}
fn begin(output: &mut [u8], kind: MessageType, len: usize) -> Result<(), Error> {
    if output.len() < len {
        return Err(Error::Capacity);
    }
    MessageHeader::from_total_size(kind, len)?.encode(output)?;
    Ok(())
}
fn write_list<const N: usize>(output: &mut [u8], values: &[[u8; N]]) {
    for (out, value) in output.as_chunks_mut::<N>().0.iter_mut().zip(values) {
        out.copy_from_slice(value);
    }
}
fn client_count(total: u32, elements: &[[u8; ELEMENT_BYTES]]) -> Result<u32, Error> {
    let contained = u32::try_from(elements.len()).map_err(|_| Error::TooLarge)?;
    if total == 0 || contained == 0 || contained > total {
        return Err(Error::InvalidInput);
    }
    Ok(contained)
}

/// One exact borrowed public hash-key/signed-value element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Element<'a> {
    /// Original match key; not authentication of its source.
    pub key: &'a [u8; HASH_BYTES],
    /// Signed two's-complement value decoded from NBO.
    pub value: i64,
}
impl<'a> Element<'a> {
    /// Read one fixed wire element without aligned casts or allocation.
    pub fn decode(input: &'a [u8; ELEMENT_BYTES]) -> Result<Self, Error> {
        Ok(Self {
            key: array(input, 0)?,
            value: i64::from_be_bytes(*array(input, HASH_BYTES)?),
        })
    }
    /// Encode one element into fixed caller-owned wire storage.
    #[must_use]
    pub fn encode(self) -> [u8; ELEMENT_BYTES] {
        let mut out = [0; ELEMENT_BYTES];
        out[..HASH_BYTES].copy_from_slice(self.key);
        out[HASH_BYTES..].copy_from_slice(&self.value.to_be_bytes());
        out
    }
}

/// Normal client operations. Closing the original computation MQ cancels it;
/// there is no scalarproduct CANCEL or processing-ACK frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientRequest<'a> {
    /// Start a requester/Alice computation640.
    Alice {
        /// Original total across this initial frame and later Alice parts.
        total: u32,
        /// Reference producers set zero; preserved as an uninterpreted field.
        reserved: u32,
        /// Original public session identifier.
        session: &'a [u8; HASH_BYTES],
        /// Actual target peer identity.
        peer: &'a [u8; PEER_BYTES],
        /// This frame's exact elements, including any zero values.
        elements: &'a [[u8; ELEMENT_BYTES]],
    },
    /// Offer a responder/Bob computation641.
    Bob {
        /// Original total across this initial frame and later Bob parts.
        total: u32,
        /// Reference producers set zero; preserved without new authorization.
        reserved: u32,
        /// Original public session identifier.
        session: &'a [u8; HASH_BYTES],
        /// This frame's exact elements.
        elements: &'a [[u8; ELEMENT_BYTES]],
    },
    /// Additional requester elements642, belonging to its original MQ/session.
    AlicePart {
        /// Exact contained elements; original aggregate bounds are owner state.
        elements: &'a [[u8; ELEMENT_BYTES]],
    },
    /// Additional responder elements643, belonging to its original MQ/session.
    BobPart {
        /// Exact contained elements; no private RID or replacement session.
        elements: &'a [[u8; ELEMENT_BYTES]],
    },
}
impl<'a> ClientRequest<'a> {
    /// Decode one complete normal IPC frame with an exact contained count.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        let request = match f.header().message_type() {
            mt::SCALARPRODUCT_CLIENT_TO_ALICE => {
                let elements = list(input, 112)?;
                count(elements.len(), number(input, 8)?, 1, 0)?;
                let total = number(input, 4)?;
                client_count(total, elements)?;
                Self::Alice {
                    total,
                    reserved: number(input, 12)?,
                    session: array(input, 16)?,
                    peer: array(input, 80)?,
                    elements,
                }
            }
            mt::SCALARPRODUCT_CLIENT_TO_BOB => {
                let elements = list(input, 80)?;
                count(elements.len(), number(input, 8)?, 1, 0)?;
                let total = number(input, 4)?;
                client_count(total, elements)?;
                Self::Bob {
                    total,
                    reserved: number(input, 12)?,
                    session: array(input, 16)?,
                    elements,
                }
            }
            mt::SCALARPRODUCT_CLIENT_MULTIPART_ALICE | mt::SCALARPRODUCT_CLIENT_MULTIPART_BOB => {
                let elements = list(input, 8)?;
                count(elements.len(), number(input, 4)?, 1, 0)?;
                if elements.is_empty() {
                    return Err(Error::Malformed);
                }
                if f.header().message_type() == mt::SCALARPRODUCT_CLIENT_MULTIPART_ALICE {
                    Self::AlicePart { elements }
                } else {
                    Self::BobPart { elements }
                }
            }
            _ => return Err(Error::Unsupported),
        };
        Ok(request)
    }
    /// The public message assignment for this actual role and part.
    #[must_use]
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::Alice { .. } => mt::SCALARPRODUCT_CLIENT_TO_ALICE,
            Self::Bob { .. } => mt::SCALARPRODUCT_CLIENT_TO_BOB,
            Self::AlicePart { .. } => mt::SCALARPRODUCT_CLIENT_MULTIPART_ALICE,
            Self::BobPart { .. } => mt::SCALARPRODUCT_CLIENT_MULTIPART_BOB,
        }
    }
    /// Exact elements carried by this frame, without dropping zeros/duplicates.
    #[must_use]
    pub const fn elements(self) -> &'a [[u8; ELEMENT_BYTES]] {
        match self {
            Self::Alice { elements, .. }
            | Self::Bob { elements, .. }
            | Self::AlicePart { elements }
            | Self::BobPart { elements } => elements,
        }
    }
    /// Whole bounded frame size. The owner checks multipart cumulative totals.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let prefix = match self {
            Self::Alice {
                total, elements, ..
            } => {
                client_count(total, elements)?;
                112
            }
            Self::Bob {
                total, elements, ..
            } => {
                client_count(total, elements)?;
                80
            }
            Self::AlicePart { elements } | Self::BobPart { elements } => {
                if elements.is_empty() {
                    return Err(Error::InvalidInput);
                }
                8
            }
        };
        extent(
            self.message_type(),
            prefix,
            ELEMENT_BYTES,
            self.elements().len(),
        )
    }
    /// Preflight before writing any output byte; no allocation or native effect.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let len = self.encoded_len()?;
        begin(output, self.message_type(), len)?;
        let elements = self.elements();
        let start = match self {
            Self::Alice {
                total,
                reserved,
                session,
                peer,
                ..
            } => {
                output[4..8].copy_from_slice(&total.to_be_bytes());
                output[8..12].copy_from_slice(&(elements.len() as u32).to_be_bytes());
                output[12..16].copy_from_slice(&reserved.to_be_bytes());
                output[16..80].copy_from_slice(session);
                output[80..112].copy_from_slice(peer);
                112
            }
            Self::Bob {
                total,
                reserved,
                session,
                ..
            } => {
                output[4..8].copy_from_slice(&total.to_be_bytes());
                output[8..12].copy_from_slice(&(elements.len() as u32).to_be_bytes());
                output[12..16].copy_from_slice(&reserved.to_be_bytes());
                output[16..80].copy_from_slice(session);
                80
            }
            _ => {
                output[4..8].copy_from_slice(&(elements.len() as u32).to_be_bytes());
                8
            }
        };
        write_list(&mut output[start..len], elements);
        Ok(len)
    }
}

/// Original scalarproduct status number, retained even for unknown statuses.
/// Interpretation of a terminal result belongs to its original computation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseStatus(pub u32);
impl ResponseStatus {
    /// Successful computation; still requires the actual original role/result.
    pub const SUCCESS: Self = Self(2);
    /// Computation failed.
    pub const FAILURE: Self = Self(3);
    /// Public invalid-response notification.
    pub const INVALID_RESPONSE: Self = Self(4);
    /// Public source-disconnection notification.
    pub const DISCONNECTED: Self = Self(5);
}
/// Actual IPC649 result/notification. The original signed GCRYMPI_FMT_STD
/// product bytes and independent range field remain opaque to the wire layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientResponse<'a> {
    /// Original status, not inferred from product length or socket EOF.
    pub status: ResponseStatus,
    /// Reference producer uses -1/0/1. Retained as its original signed NBO word.
    pub range: i32,
    /// Exact original product bytes, empty for zero or responder notification.
    pub product: &'a [u8],
}
impl<'a> ClientResponse<'a> {
    /// Exact frame/length decoding; no MPI scan or synthetic successful result.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type() != mt::SCALARPRODUCT_RESULT {
            return Err(Error::Unsupported);
        }
        let product = input.get(16..).ok_or(Error::Truncated)?;
        count(product.len(), number(input, 4)?, 1, 0)?;
        Ok(Self {
            status: ResponseStatus(number(input, 8)?),
            range: i32::from_be_bytes(*array(input, 12)?),
            product,
        })
    }
    /// Whole ordinary frame size including the product extent.
    pub fn encoded_len(self) -> Result<usize, Error> {
        extent(mt::SCALARPRODUCT_RESULT, 16, 1, self.product.len())
    }
    /// Encode the exact original terminal fields after complete preflight.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let len = self.encoded_len()?;
        begin(output, mt::SCALARPRODUCT_RESULT, len)?;
        output[4..8].copy_from_slice(&(self.product.len() as u32).to_be_bytes());
        output[8..12].copy_from_slice(&self.status.0.to_be_bytes());
        output[12..16].copy_from_slice(&self.range.to_be_bytes());
        output[16..len].copy_from_slice(self.product);
        Ok(len)
    }
}

/// Actual CADET peer messages for the two installed cryptographic profiles.
/// Profile selection is explicit; no negotiation or fallback is invented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerMessage<'a> {
    /// ECC650 session initiation; the actual remote peer comes from CADET.
    EccSession {
        /// Reference producers set zero, exposed without authentication meaning.
        reserved: u32,
        /// Original session identifier.
        session: &'a [u8; HASH_BYTES],
    },
    /// ECC651: two point columns per contained vector element.
    EccAlice {
        /// Actual point bytes in their original producer order, even and nonempty.
        points: &'a [[u8; POINT_BYTES]],
    },
    /// ECC652: precisely two result points; declared contained count is two.
    EccBob {
        /// Original product of g_i raised to b_i.
        product_g: &'a [u8; POINT_BYTES],
        /// Original product of h_i raised to b_i.
        product_h: &'a [u8; POINT_BYTES],
    },
    /// Paillier644: session and actual original 2048-bit modulus bytes.
    PaillierSession {
        /// Reference producers set zero.
        reserved: u32,
        /// Original session identifier.
        session: &'a [u8; HASH_BYTES],
        /// Public modulus bytes; validated by the cryptographic owner.
        public_key: &'a [u8; PAILLIER_KEY_BYTES],
    },
    /// Paillier645: one ciphertext per contained vector element.
    PaillierAlice {
        /// Exact original ciphertext bytes; nonempty for Alice's normal chunks.
        values: &'a [[u8; CIPHERTEXT_BYTES]],
    },
    /// Paillier647: s, s-prime and two ciphertext columns for contained entries.
    PaillierBob {
        /// Two base values plus an even number of entry values, order unchanged.
        values: &'a [[u8; CIPHERTEXT_BYTES]],
    },
    /// Paillier648: two columns for additional entries, without s/s-prime.
    PaillierBobPart {
        /// Exact original even number of values; aggregate totals are owner state.
        values: &'a [[u8; CIPHERTEXT_BYTES]],
    },
}
impl<'a> PeerMessage<'a> {
    /// Decode one complete CADET payload frame. This establishes no session or
    /// curve/modulus validity and does not execute cryptographic operations.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        match f.header().message_type() {
            mt::SCALARPRODUCT_ECC_SESSION_INITIALIZATION => {
                fixed(input, 72)?;
                Ok(Self::EccSession {
                    reserved: number(input, 4)?,
                    session: array(input, 8)?,
                })
            }
            mt::SCALARPRODUCT_ECC_ALICE_CRYPTODATA => {
                let points = list(input, 8)?;
                count(points.len(), number(input, 4)?, 2, 0)?;
                let result = Self::EccAlice { points };
                result.encoded_len()?;
                Ok(result)
            }
            mt::SCALARPRODUCT_ECC_BOB_CRYPTODATA => {
                fixed(input, 72)?;
                count(2, number(input, 4)?, 1, 0)?;
                Ok(Self::EccBob {
                    product_g: array(input, 8)?,
                    product_h: array(input, 40)?,
                })
            }
            mt::SCALARPRODUCT_SESSION_INITIALIZATION => {
                fixed(input, 328)?;
                Ok(Self::PaillierSession {
                    reserved: number(input, 4)?,
                    session: array(input, 8)?,
                    public_key: array(input, 72)?,
                })
            }
            mt::SCALARPRODUCT_ALICE_CRYPTODATA => {
                let values = list(input, 8)?;
                count(values.len(), number(input, 4)?, 1, 0)?;
                let result = Self::PaillierAlice { values };
                result.encoded_len()?;
                Ok(result)
            }
            mt::SCALARPRODUCT_BOB_CRYPTODATA | mt::SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART => {
                let values = list(input, 8)?;
                let first = f.header().message_type() == mt::SCALARPRODUCT_BOB_CRYPTODATA;
                count(
                    values.len(),
                    number(input, 4)?,
                    2,
                    if first { 2 } else { 0 },
                )?;
                Ok(if first {
                    Self::PaillierBob { values }
                } else {
                    Self::PaillierBobPart { values }
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Original public assignment, separate for ECC and Paillier.
    #[must_use]
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::EccSession { .. } => mt::SCALARPRODUCT_ECC_SESSION_INITIALIZATION,
            Self::EccAlice { .. } => mt::SCALARPRODUCT_ECC_ALICE_CRYPTODATA,
            Self::EccBob { .. } => mt::SCALARPRODUCT_ECC_BOB_CRYPTODATA,
            Self::PaillierSession { .. } => mt::SCALARPRODUCT_SESSION_INITIALIZATION,
            Self::PaillierAlice { .. } => mt::SCALARPRODUCT_ALICE_CRYPTODATA,
            Self::PaillierBob { .. } => mt::SCALARPRODUCT_BOB_CRYPTODATA,
            Self::PaillierBobPart { .. } => mt::SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART,
        }
    }
    fn shape(self) -> Result<(usize, usize, usize), Error> {
        match self {
            Self::EccSession { .. } => Ok((72, 0, 0)),
            Self::EccBob { .. } => Ok((72, 0, 2)),
            Self::PaillierSession { .. } => Ok((328, 0, 0)),
            Self::EccAlice { points } => {
                if points.is_empty() || !points.len().is_multiple_of(2) {
                    return Err(Error::InvalidInput);
                }
                Ok((
                    8,
                    points
                        .len()
                        .checked_mul(POINT_BYTES)
                        .ok_or(Error::Overflow)?,
                    points.len() / 2,
                ))
            }
            Self::PaillierAlice { values } => {
                if values.is_empty() {
                    return Err(Error::InvalidInput);
                }
                Ok((
                    8,
                    values
                        .len()
                        .checked_mul(CIPHERTEXT_BYTES)
                        .ok_or(Error::Overflow)?,
                    values.len(),
                ))
            }
            Self::PaillierBob { values } => {
                if values.len() < 2 || !values.len().is_multiple_of(2) {
                    return Err(Error::InvalidInput);
                }
                Ok((
                    8,
                    values
                        .len()
                        .checked_mul(CIPHERTEXT_BYTES)
                        .ok_or(Error::Overflow)?,
                    (values.len() - 2) / 2,
                ))
            }
            Self::PaillierBobPart { values } => {
                if !values.len().is_multiple_of(2) {
                    return Err(Error::InvalidInput);
                }
                Ok((
                    8,
                    values
                        .len()
                        .checked_mul(CIPHERTEXT_BYTES)
                        .ok_or(Error::Overflow)?,
                    values.len() / 2,
                ))
            }
        }
    }
    /// Whole frame size after validating the exact producer count convention.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let (prefix, bytes, count) = self.shape()?;
        u32::try_from(count).map_err(|_| Error::TooLarge)?;
        extent(self.message_type(), prefix, 1, bytes)
    }
    /// Encode without allocation. Short output and invalid shapes change no byte.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let len = self.encoded_len()?;
        let (_, _, count) = self.shape()?;
        begin(output, self.message_type(), len)?;
        match self {
            Self::EccSession { reserved, session } => {
                output[4..8].copy_from_slice(&reserved.to_be_bytes());
                output[8..72].copy_from_slice(session);
            }
            Self::PaillierSession {
                reserved,
                session,
                public_key,
            } => {
                output[4..8].copy_from_slice(&reserved.to_be_bytes());
                output[8..72].copy_from_slice(session);
                output[72..328].copy_from_slice(public_key);
            }
            Self::EccBob {
                product_g,
                product_h,
            } => {
                output[4..8].copy_from_slice(&2u32.to_be_bytes());
                output[8..40].copy_from_slice(product_g);
                output[40..72].copy_from_slice(product_h);
            }
            Self::EccAlice { points } => {
                output[4..8].copy_from_slice(&(count as u32).to_be_bytes());
                write_list(&mut output[8..len], points);
            }
            Self::PaillierAlice { values }
            | Self::PaillierBob { values }
            | Self::PaillierBobPart { values } => {
                output[4..8].copy_from_slice(&(count as u32).to_be_bytes());
                write_list(&mut output[8..len], values);
            }
        }
        Ok(len)
    }
}
