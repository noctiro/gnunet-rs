//! Actual conditional OIDC artifacts from oidc_helper.c; no session/network owner.
//! Signature/PKCE verification does not itself authorize an RP or consume a ticket.
use gnunet_gnsrecord::{ZoneKey, ZoneKeyType};
use gnunet_reclaim::{AttributeList, ListLimits, PresentationList, Ticket, Uri};
use gnunet_types::Error;
use gnunet_wire::official::identity::{KeyType, SecretKeyView};
use zeroize::{Zeroize, Zeroizing};
pub mod base64;

struct Scratch<'a>(&'a mut [u8]);
impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
/// Actual GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN.
pub const CODE_PURPOSE: u32 = 27;
/// Header8 + OIDC_Parameters(ticket128 + four BE32 lengths).
pub const CODE_PREFIX: usize = 152;
/// BlindableKeySignature: BE32 type + raw64 signature.
pub const CODE_SIGNATURE: usize = 68;
/// Explicit artifact byte/list/string bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Complete decoded code bytes, including signature.
    pub bytes: usize,
    /// Maximum complete attrs/presentations in their checked lists.
    pub lists: ListLimits,
    /// Maximum UTF8 nonce bytes.
    pub nonce: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 65535,
            lists: ListLimits::IPC,
            nonce: 1024,
        }
    }
}
/// Complete code fields, still borrowing original caller-owned private buffers.
#[derive(Clone, Copy)]
pub struct Code<'a> {
    /// Original actual RECLAIM ticket.
    pub ticket: Ticket<'a>,
    /// Original optional nonce, excluding NUL.
    pub nonce: &'a [u8],
    /// Empty, or exact canonical S256 PKCE challenge.
    pub challenge: &'a [u8],
    /// Actual selected attributes, not an invented scope result.
    pub attributes: AttributeList<'a>,
    /// Actual presentations bound by their own credential IDs.
    pub presentations: PresentationList<'a>,
}
impl<'a> Code<'a> {
    /// Complete decoded code size after original field/limit checks.
    pub fn encoded_len(self, limits: Limits) -> Result<usize, Error> {
        validate_strings(self, limits)?;
        let n = CODE_PREFIX
            .checked_add(self.challenge.len())
            .and_then(|n| n.checked_add(self.nonce.len()))
            .and_then(|n| n.checked_add(self.attributes.encoded_len()))
            .and_then(|n| n.checked_add(self.presentations.encoded_len()))
            .and_then(|n| n.checked_add(CODE_SIGNATURE))
            .ok_or(Error::Overflow)?;
        if n > limits.bytes {
            return Err(Error::Capacity);
        }
        u32::try_from(n - CODE_SIGNATURE).map_err(|_| Error::TooLarge)?;
        Ok(n)
    }
    /// Build and truly sign the original purpose27 artifact using explicit typed
    /// private material. Complete scratch is zeroized on success/error/Drop; output
    /// changes only after a successful signature. No key is read/generated here.
    pub fn sign(
        self,
        key: SecretKeyView<'_>,
        scratch: &mut [u8],
        out: &mut [u8],
        limits: Limits,
    ) -> Result<usize, Error> {
        let stage = Scratch(scratch);
        stage.0.zeroize();
        let n = self.encoded_len(limits)?;
        if n > out.len() || n - CODE_SIGNATURE > stage.0.len() {
            return Err(Error::Capacity);
        }
        let signed = n - CODE_SIGNATURE;
        stage.0[..4].copy_from_slice(&(signed as u32).to_be_bytes());
        stage.0[4..8].copy_from_slice(&CODE_PURPOSE.to_be_bytes());
        stage.0[8..136].fill(0);
        self.ticket.encode(&mut stage.0[8..136])?;
        for (at, len) in [
            (136, self.nonce.len()),
            (140, self.challenge.len()),
            (144, self.attributes.encoded_len()),
            (148, self.presentations.encoded_len()),
        ] {
            stage.0[at..at + 4].copy_from_slice(
                &u32::try_from(len)
                    .map_err(|_| Error::TooLarge)?
                    .to_be_bytes(),
            );
        }
        let mut at = CODE_PREFIX;
        for bytes in [
            self.challenge,
            self.nonce,
            self.attributes.expose_serialized(),
            self.presentations.expose_serialized(),
        ] {
            stage.0[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        }
        let mut material = Zeroizing::new([0u8; 32]);
        material.copy_from_slice(&key.expose_serialized()[4..]);
        let issuer = issuer(self.ticket)?;
        let signature = match key.key_type() {
            KeyType::Ecdsa => {
                let key = gnunet_crypto::gns::PkeySecret::from_bytes(*material)?;
                if issuer != ZoneKey::new(ZoneKeyType::Pkey, key.public_key()) {
                    return Err(Error::Authentication);
                }
                key.sign(CODE_PURPOSE, &[&stage.0[..signed]])?
            }
            KeyType::Eddsa => {
                let key = gnunet_crypto::EddsaPrivateKey::from_seed(*material);
                if issuer != ZoneKey::new(ZoneKeyType::Edkey, *key.public_key().as_bytes()) {
                    return Err(Error::Authentication);
                }
                *key.sign(CODE_PURPOSE, &stage.0[..signed])?.as_bytes()
            }
        };
        out[..signed].copy_from_slice(&stage.0[..signed]);
        out[signed..signed + 4].copy_from_slice(&key.key_type().value().to_be_bytes());
        out[signed + 4..n].copy_from_slice(&signature);
        Ok(n)
    }
}
/// Structurally checked complete artifact, which has NOT passed issuer/PKCE checks.
pub struct Unverified<'a> {
    bytes: &'a [u8],
    code: Code<'a>,
    signature: &'a [u8; 64],
    signature_kind: u32,
    signed: usize,
}
impl<'a> Unverified<'a> {
    /// Parse all lengths/list bodies before deriving the issuer from the decoded
    /// ticket. C's output-before-copy issuer bug is deliberately not reproduced.
    pub fn decode(bytes: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if bytes.len() > limits.bytes {
            return Err(Error::Capacity);
        }
        if bytes.len() < CODE_PREFIX + CODE_SIGNATURE {
            return Err(Error::Truncated);
        }
        let signed =
            u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error::Malformed)?) as usize;
        if signed.checked_add(CODE_SIGNATURE) != Some(bytes.len())
            || signed < CODE_PREFIX
            || u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| Error::Malformed)?)
                != CODE_PURPOSE
        {
            return Err(Error::Malformed);
        }
        let array = &bytes[8..136];
        let end = array.iter().position(|b| *b == 0).ok_or(Error::Malformed)?;
        if array[end..].iter().any(|b| *b != 0) {
            return Err(Error::Malformed);
        }
        let ticket = Ticket::new(&array[..end])?;
        let read = |at: usize| -> Result<usize, Error> {
            Ok(
                u32::from_be_bytes(bytes[at..at + 4].try_into().map_err(|_| Error::Malformed)?)
                    as usize,
            )
        };
        let nonce_len = read(136)?;
        let challenge_len = read(140)?;
        let attributes_len = read(144)?;
        let presentations_len = read(148)?;
        let mut at = CODE_PREFIX;
        let mut take = |len: usize| -> Result<&'a [u8], Error> {
            let end = at.checked_add(len).ok_or(Error::Overflow)?;
            if end > signed {
                return Err(Error::Truncated);
            }
            let value = &bytes[at..end];
            at = end;
            Ok(value)
        };
        let challenge = take(challenge_len)?;
        let nonce = take(nonce_len)?;
        let attributes = AttributeList::new(take(attributes_len)?, limits.lists)?;
        let presentations = PresentationList::new(take(presentations_len)?, limits.lists)?;
        if at != signed {
            return Err(Error::Malformed);
        }
        let code = Code {
            ticket,
            nonce,
            challenge,
            attributes,
            presentations,
        };
        validate_strings(code, limits)?;
        let signature_kind = u32::from_be_bytes(
            bytes[signed..signed + 4]
                .try_into()
                .map_err(|_| Error::Malformed)?,
        );
        let signature = bytes[signed + 4..]
            .try_into()
            .map_err(|_| Error::Malformed)?;
        Ok(Self {
            bytes,
            code,
            signature,
            signature_kind,
            signed,
        })
    }
    /// Verify original signature over the complete purpose/fields and strict S256
    /// PKCE if present. Audience/RP authorization and code replay/expiry checks
    /// belong to the actual bounded runtime owner, not this structural codec.
    pub fn verify(self, verifier: Option<&[u8]>) -> Result<Verified<'a>, Error> {
        let zone = issuer(self.code.ticket)?;
        if zone.kind().record_type().value() != self.signature_kind {
            return Err(Error::Authentication);
        }
        match zone.kind() {
            ZoneKeyType::Pkey => gnunet_crypto::gns::verify_pkey(
                zone.key(),
                CODE_PURPOSE,
                &[&self.bytes[..self.signed]],
                self.signature,
            )?,
            ZoneKeyType::Edkey => gnunet_crypto::gns::verify_edkey(
                zone.key(),
                CODE_PURPOSE,
                &[&self.bytes[..self.signed]],
                self.signature,
            )?,
        }
        check_pkce(self.code.challenge, verifier)?;
        Ok(Verified {
            code: self.code,
            issuer: zone,
        })
    }
}
impl core::fmt::Debug for Unverified<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UnverifiedCode([REDACTED])")
    }
}
/// Actual verified signature/PKCE result, not a ticket consumption result.
pub struct Verified<'a> {
    code: Code<'a>,
    issuer: ZoneKey,
}
impl<'a> Verified<'a> {
    /// Original complete decoded fields.
    pub const fn code(&self) -> Code<'a> {
        self.code
    }
    /// Actual verified issuer public key derived from that original ticket.
    pub const fn issuer(&self) -> ZoneKey {
        self.issuer
    }
}
fn validate_strings(code: Code<'_>, limits: Limits) -> Result<(), Error> {
    if code.nonce.len() > limits.nonce
        || code.nonce.contains(&0)
        || core::str::from_utf8(code.nonce).is_err()
    {
        return Err(Error::InvalidInput);
    }
    if !code.challenge.is_empty()
        && (code.challenge.len() != 43
            || code
                .challenge
                .iter()
                .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_')))
    {
        return Err(Error::InvalidInput);
    }
    if !code.challenge.is_empty() && base64::decoded_len(code.challenge, true)? != 32 {
        return Err(Error::InvalidInput);
    }
    if code.attributes.encoded_len() > limits.lists.bytes
        || code.presentations.encoded_len() > limits.lists.bytes
        || code.attributes.len() > limits.lists.items
        || code.presentations.len() > limits.lists.items
    {
        return Err(Error::Capacity);
    }
    Ok(())
}
/// Parse the issuer only after validating the decoded actual ticket bytes.
pub fn issuer(ticket: Ticket<'_>) -> Result<ZoneKey, Error> {
    Ok(ticket.capability()?.1)
}
/// Exact RFC7636 S256 check. Short-prefix challenges are never accepted.
pub fn check_pkce(challenge: &[u8], verifier: Option<&[u8]>) -> Result<(), Error> {
    if challenge.is_empty() {
        return Ok(());
    }
    let verifier = verifier.ok_or(Error::Authentication)?;
    if !(43..=128).contains(&verifier.len())
        || verifier
            .iter()
            .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(Error::Authentication);
    }
    let digest = gnunet_crypto::hash256(verifier);
    let mut expected = [0u8; 43];
    base64::encode(&digest, &mut expected, true, false)?;
    if challenge.len() != expected.len()
        || challenge
            .iter()
            .zip(expected)
            .fold(0, |d, (a, b)| d | (*a ^ b))
            != 0
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
/// Encode the actual C access-token format: standard padded Base64 of the full
/// zero-padded128-byte ticket, '-' and the original RP URI. No authentication is
/// implied by encoding; native consumption/owner cache must validate it later.
pub fn access_token(ticket: Ticket<'_>, uri: Uri<'_>, out: &mut [u8]) -> Result<usize, Error> {
    let b64 = base64::encoded_len(128, true)?;
    let n = b64
        .checked_add(1)
        .and_then(|n| n.checked_add(uri.expose().len()))
        .ok_or(Error::Overflow)?;
    if n > out.len() {
        return Err(Error::Capacity);
    }
    let mut raw = Zeroizing::new([0u8; 128]);
    ticket.encode(&mut *raw)?;
    base64::encode(&*raw, &mut out[..b64], false, true)?;
    out[b64] = b'-';
    out[b64 + 1..n].copy_from_slice(uri.expose());
    Ok(n)
}
/// Decode the actual access-token fields using caller ticket storage. URI
/// hyphens remain intact; C strtok's truncation of such URIs is not reproduced.
pub fn parse_access_token<'a>(
    token: &'a [u8],
    ticket: &'a mut [u8; 128],
) -> Result<(Ticket<'a>, Uri<'a>), Error> {
    let at = token
        .iter()
        .position(|b| *b == b'-')
        .ok_or(Error::Malformed)?;
    let mut raw = Zeroizing::new([0u8; 128]);
    if base64::decode(&token[..at], &mut *raw, false)? != 128 {
        return Err(Error::Malformed);
    }
    let end = raw.iter().position(|b| *b == 0).ok_or(Error::Malformed)?;
    if raw[end..].iter().any(|b| *b != 0) {
        return Err(Error::Malformed);
    }
    Ticket::new(&raw[..end])?;
    let uri = Uri::new(&token[at + 1..])?;
    ticket.copy_from_slice(&*raw);
    Ok((Ticket::new(&ticket[..end])?, uri))
}

impl core::fmt::Debug for Code<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Code([REDACTED])")
    }
}
