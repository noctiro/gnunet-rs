//! Active v0.29.1 threshold-share IPC and actual consensus element formats.
//!
//! Parsing proves shape only. It verifies no group membership, signature,
//! commitment, zero-knowledge proof, share, threshold, peer authority or result.
//! Secret-bearing borrowed shares intentionally implement neither Debug nor Clone.
//! The C share serializer copies original indices in native byte order; callers
//! select that source ABI explicitly. Its two padding bytes remain opaque on
//! read and are zeroed on new encoding. No C pointer layout is reproduced.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;

/// Official1024-bit fixed-width unsigned group element extent.
pub const FIELD_BYTES: usize = 128;
/// Official two-element ciphertext extent.
pub const CIPHERTEXT_BYTES: usize = 256;
/// Actual C serialized share header: three BE16 fields, two padding bytes,
/// one128-byte public key and one128-byte secret share.
pub const SHARE_PREFIX: usize = 264;
/// Per-participant serialized columns: peer32, sigma128, native index2.
pub const SHARE_ROW_BYTES: usize = 162;
/// Actual signed first-round commitment size.
pub const COMMIT_BYTES: usize = 424;
/// Actual signed reveal prefix, before per-peer proofs and coefficients.
pub const REVEAL_PREFIX: usize = 104;
/// One fair-encryption proof: cipher516,h128,t1=128,t2=512,z128,w256.
pub const FAIR_ENCRYPTION_BYTES: usize = 1668;
/// Complete signed reveal extent for the original roster and threshold.
/// This checks arithmetic and the signature-purpose size field only; it does
/// not validate a DKG roster, a proof, or the capacity of its selected carrier.
pub fn reveal_encoded_len(peers: usize, threshold: usize) -> Result<usize, Error> {
    let length = extent(
        extent(REVEAL_PREFIX, peers, FAIR_ENCRYPTION_BYTES)?,
        threshold,
        FIELD_BYTES,
    )?;
    u32::try_from(length.checked_sub(64).ok_or(Error::Overflow)?).map_err(|_| Error::TooLarge)?;
    Ok(length)
}
/// Actual signed partial-decryption element size.
pub const DECRYPT_ELEMENT_BYTES: usize = 872;
/// Official DKG first-round signature purpose.
pub const DKG1_PURPOSE: u32 = 21;
/// Official DKG reveal signature purpose.
pub const DKG2_PURPOSE: u32 = 22;
/// Official partial-decryption signature purpose.
pub const DECRYPTION_PURPOSE: u32 = 23;

fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<&[u8; N], Error> {
    bytes
        .get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn u16be(bytes: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(*array(bytes, at)?))
}
fn u32be(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(*array(bytes, at)?))
}
fn u64be(bytes: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(*array(bytes, at)?))
}
fn extent(prefix: usize, rows: usize, width: usize) -> Result<usize, Error> {
    rows.checked_mul(width)
        .and_then(|n| n.checked_add(prefix))
        .ok_or(Error::Overflow)
}
fn exact(bytes: &[u8], length: usize) -> Result<(), Error> {
    if bytes.len() != length {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn begin(out: &mut [u8], kind: MessageType, length: usize) -> Result<(), Error> {
    let header = MessageHeader::from_total_size(kind, length)?;
    if out.len() < length {
        return Err(Error::Capacity);
    }
    header.encode(out)?;
    Ok(())
}

/// Source ABI of the C share's memcpy'd original uint16 indices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexOrder {
    /// Little-endian original C host.
    Little,
    /// Big-endian original C host.
    Big,
}
impl IndexOrder {
    /// Explicit current-target native profile, without executing a probe.
    #[must_use]
    pub const fn native() -> Self {
        if cfg!(target_endian = "little") {
            Self::Little
        } else {
            Self::Big
        }
    }
    fn decode(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }
    fn encode(self, value: u16) -> [u8; 2] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
}

/// Original serialized share, including its private coefficient. Decoding does
/// not imply usable threshold, local membership or a cryptographically valid key.
pub struct Share<'a> {
    bytes: &'a [u8],
    peers: usize,
}
impl<'a> Share<'a> {
    /// Borrow an exactly sized share. Empty/insufficient-peer shares remain
    /// representable: the official producer can emit them on an unsuccessful DKG.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < SHARE_PREFIX {
            return Err(Error::Truncated);
        }
        let peers = usize::from(u16be(bytes, 2)?);
        exact(bytes, extent(SHARE_PREFIX, peers, SHARE_ROW_BYTES)?)?;
        Ok(Self { bytes, peers })
    }
    /// Original complete private representation; owners must erase their storage.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Original threshold, including zero if that was actually serialized.
    #[must_use]
    pub fn threshold(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }
    /// Original local peer index; equal-to-count is a possible C nonmember sentinel.
    #[must_use]
    pub fn my_peer(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }
    /// Actual serialized participant count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.peers
    }
    /// Whether this unsuccessful/empty representation has no participants.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.peers == 0
    }
    /// Original fixed-width public group key, without membership proof.
    pub fn public_key(&self) -> Result<&'a [u8; FIELD_BYTES], Error> {
        array(self.bytes, 8)
    }
    /// Original fixed-width private share. No copy or key derivation occurs.
    pub fn secret(&self) -> Result<&'a [u8; FIELD_BYTES], Error> {
        array(self.bytes, 136)
    }
    /// One actual peer in the original column, without reordering.
    pub fn peer(&self, index: usize) -> Result<Option<&'a [u8; 32]>, Error> {
        if index >= self.peers {
            return Ok(None);
        }
        array(self.bytes, extent(SHARE_PREFIX, index, 32)?).map(Some)
    }
    /// Actual exponentiated-share commitment for the same original peer index.
    pub fn sigma(&self, index: usize) -> Result<Option<&'a [u8; FIELD_BYTES]>, Error> {
        if index >= self.peers {
            return Ok(None);
        }
        let start = extent(SHARE_PREFIX, self.peers, 32)?;
        array(self.bytes, extent(start, index, FIELD_BYTES)?).map(Some)
    }
    /// Actual original DKG index, decoded in the selected C source ABI.
    pub fn original_index(&self, index: usize, order: IndexOrder) -> Result<Option<u16>, Error> {
        if index >= self.peers {
            return Ok(None);
        }
        let start = extent(SHARE_PREFIX, self.peers, 32 + FIELD_BYTES)?;
        Ok(Some(
            order.decode(*array(self.bytes, extent(start, index, 2)?)?),
        ))
    }
}

/// Fields for a new actual serialized share. Private bytes are never formatted
/// or cloned; output storage remains the caller's erasure responsibility.
pub struct ShareFields<'a> {
    /// Actual selected threshold; mathematical policy is checked by the core.
    pub threshold: u16,
    /// Actual local index or original nonmember sentinel.
    pub my_peer: u16,
    /// Original actual public key.
    pub public_key: &'a [u8; FIELD_BYTES],
    /// Original actual private share.
    pub secret: &'a [u8; FIELD_BYTES],
    /// Actual participant order, including the local peer if qualified.
    pub peers: &'a [[u8; 32]],
    /// Matching actual per-peer exponentiated shares.
    pub sigmas: &'a [[u8; FIELD_BYTES]],
    /// Matching original DKG indices.
    pub original_indices: &'a [u16],
    /// Native byte order of the original source consumer.
    pub order: IndexOrder,
}
impl ShareFields<'_> {
    /// Preflight every column count and integer extent without writing storage.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        u16::try_from(self.peers.len()).map_err(|_| Error::TooLarge)?;
        if self.peers.len() != self.sigmas.len() || self.peers.len() != self.original_indices.len()
        {
            return Err(Error::InvalidInput);
        }
        extent(SHARE_PREFIX, self.peers.len(), SHARE_ROW_BYTES)
    }
    /// Encode all columns after complete preflight. Standalone shares can exceed
    /// one IPC frame; normal messages still enforce their real16-bit size field.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.encoded_len()?;
        ShareEncoder {
            threshold: self.threshold,
            my_peer: self.my_peer,
            public_key: self.public_key,
            secret: self.secret,
            peers: self.peers.len(),
            order: self.order,
        }
        .encode(out, |i| ShareRow {
            peer: self.peers[i],
            sigma: self.sigmas[i],
            original_index: self.original_indices[i],
        })
    }
}

/// One public row projected from an existing aggregate without column Vecs.
/// It contains no private scalar or protocol qualification authority.
pub struct ShareRow {
    /// Selected peer identity.
    pub peer: [u8; 32],
    /// Its exponentiated share.
    pub sigma: [u8; FIELD_BYTES],
    /// Original DKG index, independent of its selected row position.
    pub original_index: u16,
}
/// Common canonical share writer for column slices and owned aggregate rows.
/// Projection uses fixed stack storage and no new allocation.
pub struct ShareEncoder<'a> {
    /// Original threshold, including an insufficient ready-count result.
    pub threshold: u16,
    /// Selected local row or the selected-count nonmember sentinel.
    pub my_peer: u16,
    /// Aggregate public key.
    pub public_key: &'a [u8; FIELD_BYTES],
    /// Actual local private scalar; output erasure remains caller-owned.
    pub secret: &'a [u8; FIELD_BYTES],
    /// Exact selected row count.
    pub peers: usize,
    /// Original consumer's index byte order.
    pub order: IndexOrder,
}
impl ShareEncoder<'_> {
    /// Complete standalone size; no output is touched on count overflow.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        u16::try_from(self.peers).map_err(|_| Error::TooLarge)?;
        extent(SHARE_PREFIX, self.peers, SHARE_ROW_BYTES)
    }
    /// Preflight size then visit each row once, writing its canonical columns.
    /// No semantic policy is added at this encoding boundary.
    pub fn encode(
        &self,
        out: &mut [u8],
        mut row: impl FnMut(usize) -> ShareRow,
    ) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        out[..n].fill(0);
        out[..2].copy_from_slice(&self.threshold.to_be_bytes());
        let peers = u16::try_from(self.peers).map_err(|_| Error::TooLarge)?;
        out[2..4].copy_from_slice(&peers.to_be_bytes());
        out[4..6].copy_from_slice(&self.my_peer.to_be_bytes());
        out[8..136].copy_from_slice(self.public_key);
        out[136..264].copy_from_slice(self.secret);
        let sigma_base = SHARE_PREFIX + 32 * self.peers;
        let index_base = sigma_base + FIELD_BYTES * self.peers;
        for i in 0..self.peers {
            let value = row(i);
            let peer_at = SHARE_PREFIX + 32 * i;
            let sigma_at = sigma_base + FIELD_BYTES * i;
            let index_at = index_base + 2 * i;
            out[peer_at..peer_at + 32].copy_from_slice(&value.peer);
            out[sigma_at..sigma_at + FIELD_BYTES].copy_from_slice(&value.sigma);
            out[index_at..index_at + 2].copy_from_slice(&self.order.encode(value.original_index));
        }
        Ok(n)
    }
    /// Encode the same canonical share directly in its standard783 response,
    /// without an intermediate private-share buffer or second serialization.
    pub fn encode_secret_ready(
        &self,
        out: &mut [u8],
        row: impl FnMut(usize) -> ShareRow,
    ) -> Result<usize, Error> {
        let n = self.encoded_len()?.checked_add(4).ok_or(Error::Overflow)?;
        begin(out, mt::SECRETSHARING_CLIENT_SECRET_READY, n)?;
        self.encode(&mut out[4..n], row)?;
        Ok(n)
    }
}

/// One normal initial threshold-generation request; no peer/session hash is
/// guessed from ordering and no deadline is interpreted as a local duration.
pub struct Generate<'a> {
    /// Exact original consensus session hash.
    pub session: &'a [u8; 64],
    /// Original absolute microsecond start.
    pub start: u64,
    /// Original absolute microsecond deadline.
    pub deadline: u64,
    /// Requested cooperating threshold, validated by the computation owner.
    pub threshold: u16,
    /// Exact peer column,32 bytes each, preserving original order.
    pub peers: &'a [u8],
}
impl Generate<'_> {
    /// Complete normal780 extent, after checking exact peer column shape.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        if !self.peers.len().is_multiple_of(32) {
            return Err(Error::InvalidInput);
        }
        u16::try_from(self.peers.len() / 32).map_err(|_| Error::TooLarge)?;
        extent(88, self.peers.len(), 1)
    }
    /// Encode the original780 request after complete shape/output preflight.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let count = u16::try_from(self.peers.len() / 32).map_err(|_| Error::TooLarge)?;
        begin(out, mt::SECRETSHARING_CLIENT_GENERATE, n)?;
        out[4..68].copy_from_slice(self.session);
        out[68..76].copy_from_slice(&self.start.to_be_bytes());
        out[76..84].copy_from_slice(&self.deadline.to_be_bytes());
        out[84..86].copy_from_slice(&self.threshold.to_be_bytes());
        out[86..88].copy_from_slice(&count.to_be_bytes());
        out[88..n].copy_from_slice(self.peers);
        Ok(n)
    }
}
/// Actual normal service requests. The decrypt request contains a private share
/// and deliberately has neither Debug nor Clone.
pub enum Request<'a> {
    /// Original780 generation intent.
    Generate(Generate<'a>),
    /// Original781 cooperative decryption intent.
    Decrypt {
        /// Original absolute start time.
        start: u64,
        /// Original absolute deadline.
        deadline: u64,
        /// Complete unmodified original ciphertext.
        ciphertext: &'a [u8; CIPHERTEXT_BYTES],
        /// Original serialized private share.
        share: Share<'a>,
    },
}
impl<'a> Request<'a> {
    /// Decode exactly one known complete official frame.
    pub fn decode(frame: Frame<'a>) -> Result<Self, Error> {
        let bytes = frame.payload();
        match frame.header().message_type() {
            mt::SECRETSHARING_CLIENT_GENERATE => {
                if bytes.len() < 84 {
                    return Err(Error::Truncated);
                }
                let peers = usize::from(u16be(bytes, 82)?);
                exact(bytes, extent(84, peers, 32)?)?;
                Ok(Self::Generate(Generate {
                    session: array(bytes, 0)?,
                    start: u64be(bytes, 64)?,
                    deadline: u64be(bytes, 72)?,
                    threshold: u16be(bytes, 80)?,
                    peers: &bytes[84..],
                }))
            }
            mt::SECRETSHARING_CLIENT_DECRYPT => {
                if bytes.len() < 272 {
                    return Err(Error::Truncated);
                }
                Ok(Self::Decrypt {
                    start: u64be(bytes, 0)?,
                    deadline: u64be(bytes, 8)?,
                    ciphertext: array(bytes, 16)?,
                    share: Share::decode(&bytes[272..])?,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Compute the complete original frame extent before any mutation.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        match self {
            Self::Generate(value) => value.encoded_len(),
            Self::Decrypt { share, .. } => extent(276, share.bytes.len(), 1),
        }
    }
    /// Encode the same original request. No hash, proof or secret is invented.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Generate(value) => value.encode(out),
            Self::Decrypt {
                start,
                deadline,
                ciphertext,
                share,
            } => {
                let n = self.encoded_len()?;
                begin(out, mt::SECRETSHARING_CLIENT_DECRYPT, n)?;
                out[4..12].copy_from_slice(&start.to_be_bytes());
                out[12..20].copy_from_slice(&deadline.to_be_bytes());
                out[20..276].copy_from_slice(*ciphertext);
                out[276..n].copy_from_slice(share.bytes);
                Ok(n)
            }
        }
    }
}
/// Actual service responses; no result is inferred from EOF/deadline.
pub enum Response<'a> {
    /// Original783 serialized private share, including empty unsuccessful shares.
    SecretReady(Share<'a>),
    /// Original782 fixed-size response. Every raw nonzero success is preserved;
    /// the consumer must validate actual decryption, not trust this flag alone.
    DecryptDone {
        /// Original raw BE32 status; ordinary C treats any nonzero as success.
        success: u32,
        /// Original fixed-width plaintext, including failed-response bytes.
        plaintext: &'a [u8; FIELD_BYTES],
    },
}
impl<'a> Response<'a> {
    /// Decode one exact known complete frame, preserving actual fields.
    pub fn decode(frame: Frame<'a>) -> Result<Self, Error> {
        let bytes = frame.payload();
        match frame.header().message_type() {
            mt::SECRETSHARING_CLIENT_SECRET_READY => Ok(Self::SecretReady(Share::decode(bytes)?)),
            mt::SECRETSHARING_CLIENT_DECRYPT_DONE => {
                exact(bytes, 132)?;
                Ok(Self::DecryptDone {
                    success: u32be(bytes, 0)?,
                    plaintext: array(bytes, 4)?,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Complete response size before output admission.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        match self {
            Self::SecretReady(share) => extent(4, share.bytes.len(), 1),
            Self::DecryptDone { .. } => Ok(136),
        }
    }
    /// Encode the actual supplied response, without validating its mathematics.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        match self {
            Self::SecretReady(share) => {
                begin(out, mt::SECRETSHARING_CLIENT_SECRET_READY, n)?;
                out[4..n].copy_from_slice(share.bytes);
            }
            Self::DecryptDone { success, plaintext } => {
                begin(out, mt::SECRETSHARING_CLIENT_DECRYPT_DONE, n)?;
                out[4..8].copy_from_slice(&success.to_be_bytes());
                out[8..136].copy_from_slice(*plaintext);
            }
        }
        Ok(n)
    }
}

/// Borrowed signed consensus element. Only canonical purpose/length and field
/// placement are checked. The original EdDSA signature is not verified here.
pub struct SignedElement<'a> {
    bytes: &'a [u8],
    purpose: u32,
    peers: usize,
    threshold: usize,
}
impl<'a> SignedElement<'a> {
    fn checked(bytes: &'a [u8], purpose: u32, length: usize) -> Result<Self, Error> {
        exact(bytes, length)?;
        if usize::try_from(u32be(bytes, 64)?).map_err(|_| Error::TooLarge)?
            != length.checked_sub(64).ok_or(Error::Malformed)?
            || u32be(bytes, 68)? != purpose
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            bytes,
            purpose,
            peers: 0,
            threshold: 0,
        })
    }
    /// Decode the real424-byte signed first-round commitment.
    pub fn commitment(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::checked(bytes, DKG1_PURPOSE, COMMIT_BYTES)
    }
    /// Decode the real104+1668*peers+128*threshold reveal shape for the original
    /// DKG roster. Neither count is inferred from an untrusted inner element.
    pub fn reveal(bytes: &'a [u8], peers: usize, threshold: usize) -> Result<Self, Error> {
        let mut element =
            Self::checked(bytes, DKG2_PURPOSE, reveal_encoded_len(peers, threshold)?)?;
        element.peers = peers;
        element.threshold = threshold;
        Ok(element)
    }
    /// Decode the real872-byte signed partial decryption.
    pub fn decryption(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::checked(bytes, DECRYPTION_PURPOSE, DECRYPT_ELEMENT_BYTES)
    }
    /// Original64-byte EdDSA signature.
    pub fn signature(&self) -> Result<&'a [u8; 64], Error> {
        array(self.bytes, 0)
    }
    /// Exact original signed bytes, including the standard purpose header.
    #[must_use]
    pub fn signed_bytes(&self) -> &'a [u8] {
        &self.bytes[64..]
    }
    /// Exact complete original consensus element bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Checked official purpose; still not evidence of signature authenticity.
    #[must_use]
    pub const fn purpose(&self) -> u32 {
        self.purpose
    }
    /// Actual signer peer in the appropriate canonical element field.
    pub fn peer(&self) -> Result<&'a [u8; 32], Error> {
        array(
            self.bytes,
            if self.purpose == DECRYPTION_PURPOSE {
                328
            } else {
                72
            },
        )
    }
    /// Actual per-peer original fair-encryption proof, in the fixed DKG roster.
    pub fn encryption(&self, index: usize) -> Result<Option<FairEncryption<'a>>, Error> {
        if self.purpose != DKG2_PURPOSE {
            return Err(Error::Conflict);
        }
        if index >= self.peers {
            return Ok(None);
        }
        let at = extent(REVEAL_PREFIX, index, FAIR_ENCRYPTION_BYTES)?;
        FairEncryption::decode(
            self.bytes
                .get(at..at + FAIR_ENCRYPTION_BYTES)
                .ok_or(Error::Truncated)?,
        )
        .map(Some)
    }
    /// Actual exponentiated polynomial coefficient from the original reveal.
    pub fn coefficient(&self, index: usize) -> Result<Option<&'a [u8; FIELD_BYTES]>, Error> {
        if self.purpose != DKG2_PURPOSE {
            return Err(Error::Conflict);
        }
        if index >= self.threshold {
            return Ok(None);
        }
        array(
            self.bytes,
            extent(
                extent(REVEAL_PREFIX, self.peers, FAIR_ENCRYPTION_BYTES)?,
                index,
                FIELD_BYTES,
            )?,
        )
        .map(Some)
    }
    /// Actual original ciphertext in the signed decryption transcript.
    pub fn ciphertext(&self) -> Result<&'a [u8; CIPHERTEXT_BYTES], Error> {
        if self.purpose != DECRYPTION_PURPOSE {
            return Err(Error::Conflict);
        }
        array(self.bytes, 72)
    }
    /// Exact SHA512 challenge input used by the original decryption proof:
    /// ciphertext, peer, partial decryption and both commitments; no response.
    pub fn decryption_challenge_bytes(&self) -> Result<&'a [u8], Error> {
        if self.purpose != DECRYPTION_PURPOSE {
            return Err(Error::Conflict);
        }
        Ok(&self.bytes[72..744])
    }
    /// Original partial decryption or proof field:0=partial,1/2=commitments,
    ///3=response. This is an offset selector, not mathematical validation.
    pub fn decryption_field(&self, index: usize) -> Result<Option<&'a [u8; FIELD_BYTES]>, Error> {
        if self.purpose != DECRYPTION_PURPOSE {
            return Err(Error::Conflict);
        }
        if index >= 4 {
            return Ok(None);
        }
        array(self.bytes, extent(360, index, FIELD_BYTES)?).map(Some)
    }
    /// Actual original first-round Paillier modulus; no primality is implied.
    pub fn paillier_key(&self) -> Result<&'a [u8; 256], Error> {
        if self.purpose != DKG1_PURPOSE {
            return Err(Error::Conflict);
        }
        array(self.bytes, 104)
    }
    /// Actual original first-round presecret commitment hash.
    pub fn commitment_hash(&self) -> Result<&'a [u8; 64], Error> {
        if self.purpose != DKG1_PURPOSE {
            return Err(Error::Conflict);
        }
        array(self.bytes, 360)
    }
}

/// Actual public fair-encryption proof fields, before any proof verification.
#[derive(Clone, Copy)]
pub struct FairEncryption<'a> {
    bytes: &'a [u8; FAIR_ENCRYPTION_BYTES],
}
impl<'a> FairEncryption<'a> {
    /// Borrow one exact original proof. No modulus or transcript is substituted.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        exact(bytes, FAIR_ENCRYPTION_BYTES)?;
        Ok(Self {
            bytes: array(bytes, 0)?,
        })
    }
    /// Complete unchanged original proof bytes.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8; FAIR_ENCRYPTION_BYTES] {
        self.bytes
    }
    /// Original official516-byte Paillier ciphertext including its operation count.
    pub fn ciphertext(self) -> Result<&'a [u8; 516], Error> {
        array(self.bytes, 0)
    }
    /// Original h=g^x, without a group-membership or knowledge proof.
    pub fn h(self) -> Result<&'a [u8; 128], Error> {
        array(self.bytes, 516)
    }
    /// Original first group commitment.
    pub fn t1(self) -> Result<&'a [u8; 128], Error> {
        array(self.bytes, 644)
    }
    /// Original512-byte Paillier-group commitment.
    pub fn t2(self) -> Result<&'a [u8; 512], Error> {
        array(self.bytes, 772)
    }
    /// Original bounded response z, before checking its range/equations.
    pub fn z(self) -> Result<&'a [u8; 128], Error> {
        array(self.bytes, 1284)
    }
    /// Original256-byte response w, before checking its range/equations.
    pub fn w(self) -> Result<&'a [u8; 256], Error> {
        array(self.bytes, 1412)
    }
}

/// Original fixed fair-encryption fields. Encoding preserves their exact
/// widths without granting equation, knowledge or range-proof validity.
pub struct FairEncryptionFields<'a> {
    /// Complete ciphertext, including its original signed operation counter.
    pub ciphertext: &'a [u8; 516],
    /// Group statement.
    pub h: &'a [u8; 128],
    /// First group commitment.
    pub t1: &'a [u8; 128],
    /// Paillier-group commitment.
    pub t2: &'a [u8; 512],
    /// Original1024-bit response, never silently truncated.
    pub z: &'a [u8; 128],
    /// Original2048-bit response.
    pub w: &'a [u8; 256],
}
impl FairEncryptionFields<'_> {
    /// Preflight storage then encode the same fields read by FairEncryption.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < FAIR_ENCRYPTION_BYTES {
            return Err(Error::Capacity);
        }
        out[..516].copy_from_slice(self.ciphertext);
        out[516..644].copy_from_slice(self.h);
        out[644..772].copy_from_slice(self.t1);
        out[772..1284].copy_from_slice(self.t2);
        out[1284..1412].copy_from_slice(self.z);
        out[1412..1668].copy_from_slice(self.w);
        Ok(FAIR_ENCRYPTION_BYTES)
    }
}

fn signed_prefix(
    out: &mut [u8],
    length: usize,
    purpose: u32,
    signature: &[u8; 64],
) -> Result<(), Error> {
    let size = u32::try_from(length.checked_sub(64).ok_or(Error::InvalidInput)?)
        .map_err(|_| Error::TooLarge)?;
    if out.len() < length {
        return Err(Error::Capacity);
    }
    out[..64].copy_from_slice(signature);
    out[64..68].copy_from_slice(&size.to_be_bytes());
    out[68..72].copy_from_slice(&purpose.to_be_bytes());
    Ok(())
}
/// Supplied actual first-round public commitment fields. Encoding does not sign
/// or prove the relation between the presecret hash and the ephemeral modulus.
pub struct CommitmentFields<'a> {
    /// Actual signature over the standard purpose and following fields.
    pub signature: &'a [u8; 64],
    /// Actual original participant signer.
    pub peer: &'a [u8; 32],
    /// Actual original256-byte Paillier public modulus.
    pub paillier_key: &'a [u8; 256],
    /// Actual original presecret commitment hash.
    pub commitment: &'a [u8; 64],
}
impl CommitmentFields<'_> {
    /// Encode the canonical424-byte element after complete output preflight.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        signed_prefix(out, COMMIT_BYTES, DKG1_PURPOSE, self.signature)?;
        out[72..104].copy_from_slice(self.peer);
        out[104..360].copy_from_slice(self.paillier_key);
        out[360..424].copy_from_slice(self.commitment);
        Ok(COMMIT_BYTES)
    }
}
/// Initialize the original signed-reveal prefix for incremental producers.
/// The complete original extent and output storage are checked before any
/// prefix write; caller-owned proof/coefficient slots remain unchanged.
pub fn encode_reveal_prefix(
    out: &mut [u8],
    signature: &[u8; 64],
    peer: &[u8; 32],
    recipients: usize,
    threshold: usize,
) -> Result<usize, Error> {
    let n = reveal_encoded_len(recipients, threshold)?;
    signed_prefix(out, n, DKG2_PURPOSE, signature)?;
    out[72..104].copy_from_slice(peer);
    Ok(n)
}

/// Actual signed reveal with immutable original roster/coefficient ordering.
/// Each supplied proof remains unverified by this codec.
pub struct RevealFields<'a> {
    /// Actual signature over the whole canonical reveal purpose/transcript.
    pub signature: &'a [u8; 64],
    /// Original actual signer peer.
    pub peer: &'a [u8; 32],
    /// One complete actual proof per original DKG participant.
    pub encryptions: &'a [[u8; FAIR_ENCRYPTION_BYTES]],
    /// Actual exponentiated polynomial coefficients, count=original threshold.
    pub coefficients: &'a [[u8; FIELD_BYTES]],
}
impl RevealFields<'_> {
    /// Complete actual extent, without changing the roster or threshold.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        reveal_encoded_len(self.encryptions.len(), self.coefficients.len())
    }
    /// Encode the canonical signed reveal after complete size/output preflight.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = encode_reveal_prefix(
            out,
            self.signature,
            self.peer,
            self.encryptions.len(),
            self.coefficients.len(),
        )?;
        let mut at = REVEAL_PREFIX;
        for proof in self.encryptions {
            out[at..at + FAIR_ENCRYPTION_BYTES].copy_from_slice(proof);
            at += FAIR_ENCRYPTION_BYTES;
        }
        for value in self.coefficients {
            out[at..at + FIELD_BYTES].copy_from_slice(value);
            at += FIELD_BYTES;
        }
        Ok(n)
    }
}
/// Supplied actual partial-decryption and DLEQ proof fields. No local timeout or
/// partial quorum may be encoded as successful decryption by a native owner.
pub struct DecryptionFields<'a> {
    /// Actual signature over the standard purpose and following full transcript.
    pub signature: &'a [u8; 64],
    /// Exact original ciphertext for this cooperative operation.
    pub ciphertext: &'a [u8; CIPHERTEXT_BYTES],
    /// Actual original participant signer.
    pub peer: &'a [u8; 32],
    /// Actual original partial decryption c1^share.
    pub partial: &'a [u8; FIELD_BYTES],
    /// Actual first proof commitment g^beta.
    pub commitment1: &'a [u8; FIELD_BYTES],
    /// Actual second proof commitment c1^beta.
    pub commitment2: &'a [u8; FIELD_BYTES],
    /// Actual original response, before verifying its proof equations.
    pub response: &'a [u8; FIELD_BYTES],
}
impl DecryptionFields<'_> {
    /// Encode the canonical872-byte element after complete output preflight.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        signed_prefix(
            out,
            DECRYPT_ELEMENT_BYTES,
            DECRYPTION_PURPOSE,
            self.signature,
        )?;
        out[72..328].copy_from_slice(self.ciphertext);
        out[328..360].copy_from_slice(self.peer);
        out[360..488].copy_from_slice(self.partial);
        out[488..616].copy_from_slice(self.commitment1);
        out[616..744].copy_from_slice(self.commitment2);
        out[744..872].copy_from_slice(self.response);
        Ok(DECRYPT_ELEMENT_BYTES)
    }
}

#[cfg(test)]
#[path = "secretsharing_tests.rs"]
mod tests;
