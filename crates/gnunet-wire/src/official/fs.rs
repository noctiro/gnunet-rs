//! Official v0.29.1 FS local service IPC (`service/fs/fs.h`).
//!
//! Local downloads use START_SEARCH, just like keyword searches. There is no
//! local GET, PUT request, cancel, result identifier or search end frame. Close
//! the operation's connection to cancel. This codec does not authenticate blocks
//! or signatures. P2P PUT has a different layout and is not decoded here.
use super::{AbsoluteTime, Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;

/// The fixed SearchMessage prefix, including the common header.
pub const SEARCH_PREFIX: usize = 112;
/// The fixed local ClientPutMessage prefix, including the common header.
pub const CLIENT_PUT_PREFIX: usize = 32;
/// Maximum number of 64-byte seen hashes in one official SearchMessage.
pub const MAX_SEEN_HASHES: usize = 1022;
/// Maximum seen hashes in a single frame, for bounded client owners.
pub const MAX_SEEN_PER_FRAME: usize = MAX_SEEN_HASHES;
/// Search with no special options.
pub const SEARCH_NONE: u32 = 0;
/// Search only the service's local datastore.
pub const SEARCH_LOOPBACK_ONLY: u32 = 1;
/// More seen hashes follow in another SearchMessage for this query.
///
/// This is a wire flag, not an owner continuation policy. The v0.29.1 service's
/// merge condition in handle_client_start_search is inconsistent with its
/// comment; callers should avoid fragmented seen sets for that service.
pub const SEARCH_CONTINUED: u32 = 2;
/// Official LOC signature purpose, GNUNET_SIGNATURE_PURPOSE_PEER_PLACEMENT.
pub const LOC_PURPOSE: u32 = 5;

/// An official block type; future response assignments remain representable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlockType(u32);
impl BlockType {
    /// Match any supported block type in a local search.
    pub const ANY: Self = Self(0);
    /// CHK tree leaf data block.
    pub const DBLOCK: Self = Self(1);
    /// CHK tree inner block.
    pub const IBLOCK: Self = Self(2);
    /// Universal keyword or namespace result block.
    pub const UBLOCK: Self = Self(9);

    /// Preserve a registry value without granting block validity.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
    /// Numeric assignment in host byte order.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// One local search or CHK block request. All hashes borrow caller storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Search<'a> {
    /// SEARCH_NONE, SEARCH_LOOPBACK_ONLY and/or SEARCH_CONTINUED.
    pub options: u32,
    /// Official block type, including ANY where appropriate.
    pub block_type: BlockType,
    /// Desired anonymity level.
    pub anonymity: u32,
    /// Known peer for D/I blocks, otherwise all zeros.
    pub target: [u8; 32],
    /// Ciphertext hash for D/I blocks or derived public-key hash for a UBLOCK.
    pub query: [u8; 64],
    /// Concatenated 64-byte hashes of already-known complete result blocks.
    pub seen: &'a [u8],
}
impl Search<'_> {
    /// Validate the defined options, target and whole seen-hash list.
    pub fn validate(self) -> Result<(), Error> {
        if self.options & !(SEARCH_LOOPBACK_ONLY | SEARCH_CONTINUED) != 0
            || !self.seen.len().is_multiple_of(64)
        {
            return Err(Error::InvalidInput);
        }
        if self.seen.len() / 64 > MAX_SEEN_HASHES {
            return Err(Error::TooLarge);
        }
        if self.block_type != BlockType::DBLOCK
            && self.block_type != BlockType::IBLOCK
            && self.target != [0; 32]
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

/// One local client request. Each operation should own its connection because
/// official FS IPC has no request identifier or per-request cancel frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Start a search, or request one encrypted D/I block.
    Search(Search<'a>),
    /// Ask the local peer to sign a LOC URI for this CHK.
    LocSign {
        /// Requested absolute expiry; the service rounds down to whole seconds.
        expiration: AbsoluteTime,
        /// CHK plaintext hash, used as its encryption key.
        key: [u8; 64],
        /// CHK ciphertext query hash.
        query: [u8; 64],
        /// Complete plaintext file length, encoded producer-native in this
        /// local IPC request to match the official publisher and service.
        file_length: u64,
    },
    /// Register a file for on-demand indexing, after service-side availability
    /// and hash or device/inode checks. This does not store DATASTORE blocks.
    IndexStart {
        /// Device ID or zero to require hashing.
        device: u64,
        /// Inode or zero to require hashing.
        inode: u64,
        /// Hash of the whole plaintext file.
        file_id: [u8; 64],
        /// OS path bytes excluding the final NUL; absolute paths are allowed.
        filename: &'a [u8],
    },
    /// Stream the indexed-file list, ending with IndexEnd.
    IndexList,
    /// Remove the file's index registration. DATASTORE removal is separate.
    Unindex {
        /// Hash of the whole plaintext file.
        file_id: [u8; 64],
    },
}
impl<'a> Request<'a> {
    /// Decode one complete local request. P2P GET and PUT are unsupported.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        match frame.header().message_type() {
            mt::FS_START_SEARCH => {
                let search = Search {
                    options: number(bytes, 4)?,
                    block_type: BlockType::new(number(bytes, 8)?),
                    anonymity: number(bytes, 12)?,
                    target: fixed(bytes, 16)?,
                    query: fixed(bytes, 48)?,
                    seen: bytes.get(SEARCH_PREFIX..).ok_or(Error::Truncated)?,
                };
                search.validate().map_err(malformed)?;
                Ok(Self::Search(search))
            }
            mt::FS_REQUEST_LOC_SIGN => {
                exact(bytes, 152)?;
                check_purpose(bytes)?;
                Ok(Self::LocSign {
                    expiration: time(bytes, 8)?,
                    key: fixed(bytes, 16)?,
                    query: fixed(bytes, 80)?,
                    // The official local publisher applies htonll to an
                    // already-network-order FileIdentifier length. Its matching
                    // service reverses that conversion before signing the NBO
                    // URI region, so this IPC field is producer-native.
                    file_length: u64::from_ne_bytes(fixed(bytes, 144)?),
                })
            }
            mt::FS_INDEX_START => {
                zero(bytes, 4)?;
                Ok(Self::IndexStart {
                    device: wide(bytes, 8)?,
                    inode: wide(bytes, 16)?,
                    file_id: fixed(bytes, 24)?,
                    filename: nul_payload(bytes, 88)?,
                })
            }
            mt::FS_INDEX_LIST_GET => {
                exact(bytes, 4)?;
                Ok(Self::IndexList)
            }
            mt::FS_UNINDEX => {
                exact(bytes, 72)?;
                zero(bytes, 4)?;
                Ok(Self::Unindex {
                    file_id: fixed(bytes, 8)?,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }

    /// Exact total frame size, with every semantic preflight performed.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.shape().map(|(_, n)| n)
    }

    /// Encode one complete request. Every rejection preserves the whole output.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let (kind, n) = self.shape()?;
        let b = prepare(kind, n, output)?;
        match self {
            Self::Search(search) => {
                b[4..8].copy_from_slice(&search.options.to_be_bytes());
                b[8..12].copy_from_slice(&search.block_type.value().to_be_bytes());
                b[12..16].copy_from_slice(&search.anonymity.to_be_bytes());
                b[16..48].copy_from_slice(&search.target);
                b[48..SEARCH_PREFIX].copy_from_slice(&search.query);
                b[SEARCH_PREFIX..].copy_from_slice(search.seen);
            }
            Self::LocSign {
                expiration,
                key,
                query,
                file_length,
            } => {
                b[4..8].copy_from_slice(&LOC_PURPOSE.to_be_bytes());
                b[8..16].copy_from_slice(&expiration.to_be_bytes());
                b[16..80].copy_from_slice(&key);
                b[80..144].copy_from_slice(&query);
                b[144..152].copy_from_slice(&file_length.to_ne_bytes());
            }
            Self::IndexStart {
                device,
                inode,
                file_id,
                filename,
            } => {
                b[4..8].fill(0);
                b[8..16].copy_from_slice(&device.to_be_bytes());
                b[16..24].copy_from_slice(&inode.to_be_bytes());
                b[24..88].copy_from_slice(&file_id);
                put_nul(&mut b[88..], filename);
            }
            Self::IndexList => {}
            Self::Unindex { file_id } => {
                b[4..8].fill(0);
                b[8..72].copy_from_slice(&file_id);
            }
        }
        Ok(n)
    }

    fn shape(self) -> Result<(MessageType, usize), Error> {
        let (kind, n) = match self {
            Self::Search(search) => {
                search.validate()?;
                (
                    mt::FS_START_SEARCH,
                    length(SEARCH_PREFIX, search.seen.len())?,
                )
            }
            Self::LocSign { .. } => (mt::FS_REQUEST_LOC_SIGN, 152),
            Self::IndexStart { filename, .. } => (mt::FS_INDEX_START, nul_length(88, filename)?),
            Self::IndexList => (mt::FS_INDEX_LIST_GET, 4),
            Self::Unindex { .. } => (mt::FS_UNINDEX, 72),
        };
        MessageHeader::from_total_size(kind, n)?;
        Ok((kind, n))
    }
}

/// A local service result. These bytes still require content authentication and
/// query/type matching. In particular, this is not the P2P PutMessage layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientPut<'a> {
    /// Nonzero block type, preserving future assignments.
    pub block_type: BlockType,
    /// Expiry of the content, not a request deadline.
    pub expiration: AbsoluteTime,
    /// Last transmission time; NEVER means unknown or irrelevant.
    pub last_transmission: AbsoluteTime,
    /// Estimated number of transmissions.
    pub num_transmissions: u32,
    /// Estimated total respect offered.
    pub respect_offered: u32,
    /// Complete encrypted D/I block or signed UBLOCK.
    pub block: &'a [u8],
}

/// A local service response. Unknown well-framed future codes are retained;
/// known local requests and P2P GET cannot be decoded as responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// Search/download result. No RID or explicit completion bit is present.
    Put(ClientPut<'a>),
    /// LOC signature with the actual rounded expiry and signing peer.
    LocSignature {
        /// Actual signed absolute expiry.
        expiration: AbsoluteTime,
        /// Raw Ed25519 signature requiring verification over the LOC purpose.
        signature: [u8; 64],
        /// Public signing peer identity.
        peer: [u8; 32],
    },
    /// Index registration succeeded.
    IndexStarted,
    /// Index registration failed with a NUL-terminated message.
    IndexFailed {
        /// Raw message bytes without the final NUL.
        message: &'a [u8],
    },
    /// One indexed file; more entries or IndexEnd follow.
    IndexEntry {
        /// Plaintext whole-file hash.
        file_id: [u8; 64],
        /// Raw OS path bytes without the final NUL.
        filename: &'a [u8],
    },
    /// The indexed-file list has ended. Search has no analogous marker.
    IndexEnd,
    /// Index registration removed, including already-absent registrations.
    Unindexed,
    /// An unknown message code with its complete official payload.
    Unknown(Frame<'a>),
}
impl<'a> Response<'a> {
    /// Decode exactly one local response, without authenticating content.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        match frame.header().message_type() {
            mt::FS_PUT => {
                let block_type = BlockType::new(number(bytes, 4)?);
                if block_type == BlockType::ANY {
                    return Err(Error::Malformed);
                }
                Ok(Self::Put(ClientPut {
                    block_type,
                    expiration: time(bytes, 8)?,
                    last_transmission: time(bytes, 16)?,
                    num_transmissions: number(bytes, 24)?,
                    respect_offered: number(bytes, 28)?,
                    block: bytes.get(CLIENT_PUT_PREFIX..).ok_or(Error::Truncated)?,
                }))
            }
            mt::FS_REQUEST_LOC_SIGNATURE => {
                exact(bytes, 112)?;
                check_purpose(bytes)?;
                Ok(Self::LocSignature {
                    expiration: time(bytes, 8)?,
                    signature: fixed(bytes, 16)?,
                    peer: fixed(bytes, 80)?,
                })
            }
            mt::FS_INDEX_START_OK => {
                exact(bytes, 4)?;
                Ok(Self::IndexStarted)
            }
            mt::FS_INDEX_START_FAILED => Ok(Self::IndexFailed {
                message: nul_payload(bytes, 4)?,
            }),
            mt::FS_INDEX_LIST_ENTRY => {
                zero(bytes, 4)?;
                Ok(Self::IndexEntry {
                    file_id: fixed(bytes, 8)?,
                    filename: nul_payload(bytes, 72)?,
                })
            }
            mt::FS_INDEX_LIST_END => {
                exact(bytes, 4)?;
                Ok(Self::IndexEnd)
            }
            mt::FS_UNINDEX_OK => {
                exact(bytes, 4)?;
                Ok(Self::Unindexed)
            }
            kind if known_local_or_p2p_get(kind) => Err(Error::Unsupported),
            _ => Ok(Self::Unknown(frame)),
        }
    }

    /// Exact encoded size, performing every semantic check first.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.shape().map(|(_, n)| n)
    }

    /// Encode one response atomically, retaining an unknown payload verbatim.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let (kind, n) = self.shape()?;
        let b = prepare(kind, n, output)?;
        match self {
            Self::Put(put) => {
                b[4..8].copy_from_slice(&put.block_type.value().to_be_bytes());
                b[8..16].copy_from_slice(&put.expiration.to_be_bytes());
                b[16..24].copy_from_slice(&put.last_transmission.to_be_bytes());
                b[24..28].copy_from_slice(&put.num_transmissions.to_be_bytes());
                b[28..32].copy_from_slice(&put.respect_offered.to_be_bytes());
                b[CLIENT_PUT_PREFIX..].copy_from_slice(put.block);
            }
            Self::LocSignature {
                expiration,
                signature,
                peer,
            } => {
                b[4..8].copy_from_slice(&LOC_PURPOSE.to_be_bytes());
                b[8..16].copy_from_slice(&expiration.to_be_bytes());
                b[16..80].copy_from_slice(&signature);
                b[80..112].copy_from_slice(&peer);
            }
            Self::IndexFailed { message } => put_nul(&mut b[4..], message),
            Self::IndexEntry { file_id, filename } => {
                b[4..8].fill(0);
                b[8..72].copy_from_slice(&file_id);
                put_nul(&mut b[72..], filename);
            }
            Self::Unknown(frame) => b[4..].copy_from_slice(frame.payload()),
            Self::IndexStarted | Self::IndexEnd | Self::Unindexed => {}
        }
        Ok(n)
    }

    fn shape(self) -> Result<(MessageType, usize), Error> {
        let (kind, n) = match self {
            Self::Put(put) => {
                if put.block_type == BlockType::ANY {
                    return Err(Error::InvalidInput);
                }
                (mt::FS_PUT, length(CLIENT_PUT_PREFIX, put.block.len())?)
            }
            Self::LocSignature { .. } => (mt::FS_REQUEST_LOC_SIGNATURE, 112),
            Self::IndexStarted => (mt::FS_INDEX_START_OK, 4),
            Self::IndexFailed { message } => (mt::FS_INDEX_START_FAILED, nul_length(4, message)?),
            Self::IndexEntry { filename, .. } => {
                (mt::FS_INDEX_LIST_ENTRY, nul_length(72, filename)?)
            }
            Self::IndexEnd => (mt::FS_INDEX_LIST_END, 4),
            Self::Unindexed => (mt::FS_UNINDEX_OK, 4),
            Self::Unknown(frame) => {
                let kind = frame.header().message_type();
                if known_local_or_p2p_get(kind) {
                    return Err(Error::InvalidInput);
                }
                (kind, frame.encoded_len())
            }
        };
        MessageHeader::from_total_size(kind, n)?;
        Ok((kind, n))
    }
}

fn known_local_or_p2p_get(kind: MessageType) -> bool {
    (126..=138).contains(&kind.value())
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
fn wide(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(fixed(bytes, offset)?))
}
fn time(bytes: &[u8], offset: usize) -> Result<AbsoluteTime, Error> {
    Ok(AbsoluteTime::from_micros(wide(bytes, offset)?))
}
fn zero(bytes: &[u8], offset: usize) -> Result<(), Error> {
    if number(bytes, offset)? != 0 {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn check_purpose(bytes: &[u8]) -> Result<(), Error> {
    if number(bytes, 4)? != LOC_PURPOSE {
        return Err(Error::Unsupported);
    }
    Ok(())
}
fn nul_payload(bytes: &[u8], prefix: usize) -> Result<&[u8], Error> {
    let payload = bytes.get(prefix..).ok_or(Error::Truncated)?;
    let (&last, value) = payload.split_last().ok_or(Error::Malformed)?;
    if last != 0 || value.contains(&0) {
        return Err(Error::Malformed);
    }
    Ok(value)
}
fn put_nul(output: &mut [u8], value: &[u8]) {
    output[..value.len()].copy_from_slice(value);
    output[value.len()] = 0;
}
fn nul_length(prefix: usize, value: &[u8]) -> Result<usize, Error> {
    if value.contains(&0) {
        return Err(Error::InvalidInput);
    }
    length(prefix, value.len().checked_add(1).ok_or(Error::Overflow)?)
}
fn length(prefix: usize, payload: usize) -> Result<usize, Error> {
    prefix.checked_add(payload).ok_or(Error::Overflow)
}
fn prepare(kind: MessageType, n: usize, output: &mut [u8]) -> Result<&mut [u8], Error> {
    let header = MessageHeader::from_total_size(kind, n)?;
    if output.len() < n {
        return Err(Error::Capacity);
    }
    header.encode(output)?;
    Ok(&mut output[..n])
}
fn malformed(error: Error) -> Error {
    match error {
        Error::InvalidInput => Error::Malformed,
        other => other,
    }
}
