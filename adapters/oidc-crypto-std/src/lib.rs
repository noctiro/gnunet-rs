//! Narrow actual RS256/HS512 OIDC bridge. RSA uses AWS-LC native/asm primitives,
//! never libgnunet FFI or a homemade private-key RSA operation. No file is opened.
#![forbid(unsafe_code)]
use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der},
    rsa::{KeyPair, KeyPairComponents, KeySize, PublicKeyComponents},
    signature::{self, KeyPair as _},
};
use gnunet_rest::oidc::base64;
use gnunet_types::Error;
use zeroize::Zeroizing;
/// Finite JWK/DER, public modulus, signed message and complete JWT bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete explicit JWK or DER input.
    pub key_bytes: usize,
    /// Maximum public modulus bytes;2048..8192-bit library bounds still apply.
    pub modulus_bytes: usize,
    /// Maximum complete original signing message/payload bytes.
    pub message_bytes: usize,
    /// Maximum complete compact JWT bytes.
    pub token_bytes: usize,
    /// Explicit bounded shared JSON validation resources.
    pub json: gnunet_json::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            key_bytes: 16384,
            modulus_bytes: 1024,
            message_bytes: 65535,
            token_bytes: 262140,
            json: gnunet_json::Limits {
                bytes: 65535,
                nodes: 4096,
                depth: 64,
                work: 4_000_000,
            },
        }
    }
}
fn buffer(n: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    v.resize(n, 0);
    Ok(Zeroizing::new(v))
}
fn json<T>(
    input: &[u8],
    limits: gnunet_json::Limits,
    f: impl for<'a> FnOnce(gnunet_json::Value<'a>) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut payload = buffer(limits.bytes)?;
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(limits.nodes)
        .map_err(|_| Error::Capacity)?;
    nodes.resize(limits.nodes, gnunet_json::Token::EMPTY);
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(limits.depth)
        .map_err(|_| Error::Capacity)?;
    stack.resize(limits.depth, gnunet_json::Nest::EMPTY);
    let mut workspace = gnunet_json::Workspace::new(&mut payload, &mut nodes, &mut stack);
    let doc = workspace.parse(input, limits)?;
    f(doc.root())
}
fn jwk<T>(
    input: &[u8],
    limits: Limits,
    private: bool,
    f: impl for<'a> FnOnce(gnunet_json::Value<'a>) -> Result<T, Error>,
) -> Result<T, Error> {
    if input.len() > limits.key_bytes {
        return Err(Error::Capacity);
    }
    json(
        input,
        gnunet_json::Limits {
            bytes: limits.key_bytes,
            nodes: 128,
            depth: 8,
            work: 1_048_576,
        },
        |root| {
            if !root
                .get(b"kty")
                .ok_or(Error::Malformed)?
                .string()?
                .eq_ascii(b"RSA")
            {
                return Err(Error::Unsupported);
            }
            if let Some(alg) = root.get(b"alg")
                && !alg.string()?.eq_ascii(b"RS256")
            {
                return Err(Error::Authentication);
            }
            if let Some(usage) = root.get(b"use")
                && !usage.string()?.eq_ascii(b"sig")
            {
                return Err(Error::Authentication);
            }
            if root.get(b"oth").is_some() {
                return Err(Error::Unsupported);
            }
            if let Some(operations) = root.get(b"key_ops") {
                let mut allowed = false;
                for op in operations.elements()? {
                    if op
                        .string()?
                        .eq_ascii(if private { b"sign" } else { b"verify" })
                    {
                        allowed = true
                    }
                }
                if !allowed {
                    return Err(Error::Authentication);
                }
            }
            f(root)
        },
    )
}
fn component(
    root: gnunet_json::Value<'_>,
    name: &[u8],
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let text = root.get(name).ok_or(Error::Malformed)?.string()?;
    let mut encoded = buffer(text.decoded_len()?)?;
    text.decode(&mut encoded)?;
    let n = base64::decoded_len(&encoded, true)?;
    if n == 0 || n > maximum {
        return Err(Error::Capacity);
    }
    let mut raw = buffer(n)?;
    base64::decode(&encoded, &mut raw, true)?;
    if raw[0] == 0 {
        return Err(Error::Malformed);
    }
    Ok(raw)
}
/// Actual caller-owned RSA signer. No Clone, secret Debug, path or ambient JWK
/// discovery is exposed. Backend owns/frees its private native key allocations.
pub struct Rsa {
    key: KeyPair,
    limits: Limits,
}
impl Rsa {
    /// Explicit fresh RSA key generation, default official size2048 when selected
    /// by the caller. This invokes AWS-LC's generator; no generation occurs by
    /// constructing Limits, importing public JSON or formatting a response.
    pub fn generate(bits: usize, limits: Limits) -> Result<Self, Error> {
        let size = match bits {
            2048 => KeySize::Rsa2048,
            3072 => KeySize::Rsa3072,
            4096 => KeySize::Rsa4096,
            8192 => KeySize::Rsa8192,
            _ => return Err(Error::Unsupported),
        };
        if bits / 8 > limits.modulus_bytes {
            return Err(Error::Capacity);
        }
        let key = KeyPair::generate(size).map_err(|_| Error::Entropy)?;
        Ok(Self { key, limits })
    }
    /// Import only explicit caller-owned PKCS8 DER. No file path/read is accepted.
    pub fn from_pkcs8(input: &[u8], limits: Limits) -> Result<Self, Error> {
        if input.len() > limits.key_bytes {
            return Err(Error::Capacity);
        }
        let key = KeyPair::from_pkcs8(input).map_err(|_| Error::Authentication)?;
        if key.public_modulus_len() > limits.modulus_bytes {
            return Err(Error::Capacity);
        }
        Ok(Self { key, limits })
    }
    /// Import exact standard two-prime RSA JWK components. All decoded private
    /// buffers are zeroized and the actual backend validates component consistency.
    pub fn from_jwk(input: &[u8], limits: Limits) -> Result<Self, Error> {
        let key = jwk(input, limits, true, |root| {
            let n = component(root, b"n", limits.modulus_bytes)?;
            let e = component(root, b"e", 5)?;
            let d = component(root, b"d", limits.modulus_bytes)?;
            let p = component(root, b"p", limits.modulus_bytes)?;
            let q = component(root, b"q", limits.modulus_bytes)?;
            let dp = component(root, b"dp", limits.modulus_bytes)?;
            let dq = component(root, b"dq", limits.modulus_bytes)?;
            let qi = component(root, b"qi", limits.modulus_bytes)?;
            KeyPair::from_components(&KeyPairComponents {
                public_key: PublicKeyComponents {
                    n: n.as_slice(),
                    e: e.as_slice(),
                },
                d: d.as_slice(),
                p: p.as_slice(),
                q: q.as_slice(),
                dP: dp.as_slice(),
                dQ: dq.as_slice(),
                qInv: qi.as_slice(),
            })
            .map_err(|_| Error::Authentication)
        })?;
        Ok(Self { key, limits })
    }
    /// Explicit bounded private export for an independently authorized owned-key
    /// provider. The backend DER owner and returned buffer erase on Drop. This
    /// does not persist, fingerprint, hash or print private key material.
    pub fn export_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let der: Pkcs8V1Der<'static> = self.key.as_der().map_err(|_| Error::NotReady)?;
        let bytes: &[u8] = der.as_ref();
        if bytes.len() > self.limits.key_bytes {
            return Err(Error::Capacity);
        }
        let mut out = buffer(bytes.len())?;
        out.copy_from_slice(bytes);
        Ok(out)
    }
    /// Actual signature width for this original provider.
    pub fn signature_bytes(&self) -> usize {
        self.key.public_modulus_len()
    }
    /// Sign one exact message with RSASSA-PKCS1v1.5/SHA256. No encryption/decryption,
    /// algorithm negotiation, HMAC fallback or arbitrary RSA primitive is exposed.
    /// AWS-LC uses its own RNG internally; the compatibility SecureRandom argument
    /// is ignored by that library, rather than falsely called caller entropy.
    pub fn sign(&self, message: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if message.len() > self.limits.message_bytes {
            return Err(Error::Capacity);
        }
        let n = self.signature_bytes();
        if n > out.len() {
            return Err(Error::Capacity);
        }
        let mut signature = buffer(n)?;
        self.key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                message,
                &mut signature,
            )
            .map_err(|_| Error::NotReady)?;
        out[..n].copy_from_slice(&signature);
        Ok(n)
    }
    /// Public JWK derived from this exact original native provider, not an unrelated
    /// regenerated key. The ring-io feature supplies existing n/e accessors.
    pub fn public(&self) -> Public {
        let parts: PublicKeyComponents<Vec<u8>> = self.key.public_key().into();
        Public {
            n: parts.n,
            e: parts.e,
            limits: self.limits,
        }
    }
    /// Produce an actual compact RS256 JWS over a validated original JSON object.
    pub fn sign_jwt(&self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        validate_payload(payload, self.limits)?;
        let input = signing_input(b"{\"alg\":\"RS256\",\"typ\":\"jwt\"}", payload, self.limits)?;
        let n = self.signature_bytes();
        let signature_encoded = base64::encoded_len(n, false)?;
        let total = input
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(signature_encoded))
            .ok_or(Error::Overflow)?;
        if total > out.len() || total > self.limits.token_bytes {
            return Err(Error::Capacity);
        }
        let mut signature = buffer(n)?;
        self.sign(&input, &mut signature)?;
        out[..input.len()].copy_from_slice(&input);
        out[input.len()] = b'.';
        base64::encode(&signature, &mut out[input.len() + 1..total], true, false)?;
        Ok(total)
    }
}
impl core::fmt::Debug for Rsa {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rsa")
            .field("backend", &"aws-lc-rs1.19.0/non-fips/native")
            .finish_non_exhaustive()
    }
}
/// Bounded public RSA material only. No private components are retained here.
pub struct Public {
    n: Vec<u8>,
    e: Vec<u8>,
    limits: Limits,
}
impl Public {
    /// Import explicit public JWK; no file, network or private provider is opened.
    pub fn from_jwk(input: &[u8], limits: Limits) -> Result<Self, Error> {
        jwk(input, limits, false, |root| {
            let n = component(root, b"n", limits.modulus_bytes)?;
            let e = component(root, b"e", 5)?;
            let copy = |b: &[u8]| -> Result<Vec<u8>, Error> {
                let mut v = Vec::new();
                v.try_reserve_exact(b.len()).map_err(|_| Error::Capacity)?;
                v.extend_from_slice(b);
                Ok(v)
            };
            if n.len() < 256 {
                return Err(Error::Authentication);
            }
            Ok(Self {
                n: copy(&n)?,
                e: copy(&e)?,
                limits,
            })
        })
    }
    /// Encode one standard public JWK. Complete output is capacity-checked first.
    pub fn write_jwk(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n64 = base64::encoded_len(self.n.len(), false)?;
        let e64 = base64::encoded_len(self.e.len(), false)?;
        let prefix = b"{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"";
        let middle = b"\",\"e\":\"";
        let tail = b"\"}";
        let total = prefix
            .len()
            .checked_add(n64)
            .and_then(|n| n.checked_add(middle.len()))
            .and_then(|n| n.checked_add(e64))
            .and_then(|n| n.checked_add(tail.len()))
            .ok_or(Error::Overflow)?;
        let out = out.get_mut(..total).ok_or(Error::Capacity)?;
        let mut at = prefix.len();
        out[..at].copy_from_slice(prefix);
        base64::encode(&self.n, &mut out[at..at + n64], true, false)?;
        at += n64;
        out[at..at + middle.len()].copy_from_slice(middle);
        at += middle.len();
        base64::encode(&self.e, &mut out[at..at + e64], true, false)?;
        at += e64;
        out[at..].copy_from_slice(tail);
        Ok(total)
    }
    /// Verify exactly RS256 with the actual backend's public operation. No private
    /// key arithmetic, padding rejection/decryption oracle or downgrade is exposed.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        if message.len() > self.limits.message_bytes || signature.len() != self.n.len() {
            return Err(Error::Capacity);
        }
        PublicKeyComponents {
            n: self.n.as_slice(),
            e: self.e.as_slice(),
        }
        .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
        .map_err(|_| Error::Authentication)
    }
    /// Verify a compact JWT's exact original RS256 header/signing input, then copy
    /// its validated payload into caller output. No issuer/audience/time claim is
    /// authorized by this signature-only operation.
    pub fn verify_jwt<'a>(
        &self,
        token: &[u8],
        out: &'a mut [u8],
    ) -> Result<VerifiedPayload<'a>, Error> {
        let TokenParts {
            signed,
            signature,
            payload,
        } = parts(token, b"RS256", self.limits)?;
        let mut raw = buffer(base64::decoded_len(signature, true)?)?;
        base64::decode(signature, &mut raw, true)?;
        self.verify(signed, &raw)?;
        decoded_payload(payload, out, self.limits).map(|bytes| VerifiedPayload {
            bytes,
            algorithm: "RS256",
        })
    }
}
impl core::fmt::Debug for Public {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RsaPublic")
            .field("modulus_bytes", &self.n.len())
            .finish_non_exhaustive()
    }
}
/// Signature-verified payload only. It does not authorize issuer, audience,
/// timestamps, nonce, replay or access policy. Caller owns and must erase output.
pub struct VerifiedPayload<'a> {
    bytes: &'a [u8],
    algorithm: &'static str,
}
impl<'a> VerifiedPayload<'a> {
    /// Explicitly expose the validated JSON payload after actual verification.
    pub const fn expose(&self) -> &'a [u8] {
        self.bytes
    }
    /// The provider explicitly selected by the caller, never an untrusted fallback.
    pub const fn algorithm(&self) -> &'static str {
        self.algorithm
    }
}
impl core::fmt::Debug for VerifiedPayload<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedPayload")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}
/// Explicit zeroizing HMAC secret. Selecting this provider never substitutes it
/// for an unavailable RSA provider or a requested RS256 algorithm.
pub struct Hs512 {
    key: Zeroizing<Vec<u8>>,
    limits: Limits,
}
impl Hs512 {
    /// Retain one explicit bounded secret copy. No file/config discovery occurs.
    pub fn new(key: &[u8], limits: Limits) -> Result<Self, Error> {
        if key.is_empty() || key.len() > limits.key_bytes {
            return Err(Error::Capacity);
        }
        let mut owned = buffer(key.len())?;
        owned.copy_from_slice(key);
        Ok(Self { key: owned, limits })
    }
    /// Actually authenticate the compact JWS using the existing zeroizing HMAC512
    /// primitive over the exact original encoded header+payload bytes.
    pub fn sign_jwt(&self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        validate_payload(payload, self.limits)?;
        let input = signing_input(b"{\"alg\":\"HS512\",\"typ\":\"jwt\"}", payload, self.limits)?;
        let total = input.len().checked_add(87).ok_or(Error::Overflow)?;
        if total > out.len() || total > self.limits.token_bytes {
            return Err(Error::Capacity);
        }
        let tag = gnunet_crypto::hmac512_parts(&self.key, &[&input]);
        out[..input.len()].copy_from_slice(&input);
        out[input.len()] = b'.';
        base64::encode(&*tag, &mut out[input.len() + 1..total], true, false)?;
        Ok(total)
    }
    /// Verify only the explicitly selected HS512 algorithm, in constant-time tag
    /// comparison; no untrusted algorithm header chooses which provider to use.
    pub fn verify_jwt<'a>(
        &self,
        token: &[u8],
        out: &'a mut [u8],
    ) -> Result<VerifiedPayload<'a>, Error> {
        let TokenParts {
            signed,
            signature,
            payload,
        } = parts(token, b"HS512", self.limits)?;
        let mut raw = Zeroizing::new([0u8; 64]);
        if base64::decode(signature, &mut *raw, true)? != 64 {
            return Err(Error::Authentication);
        }
        let expected = gnunet_crypto::hmac512_parts(&self.key, &[signed]);
        if raw
            .iter()
            .zip(expected.iter())
            .fold(0, |d, (a, b)| d | (*a ^ *b))
            != 0
        {
            return Err(Error::Authentication);
        }
        decoded_payload(payload, out, self.limits).map(|bytes| VerifiedPayload {
            bytes,
            algorithm: "HS512",
        })
    }
}
impl core::fmt::Debug for Hs512 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Hs512([REDACTED])")
    }
}
fn validate_payload(payload: &[u8], limits: Limits) -> Result<(), Error> {
    if payload.len() > limits.message_bytes {
        return Err(Error::Capacity);
    }
    json(payload, limits.json, |root| {
        if root.kind() == gnunet_json::ValueKind::Object {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    })
}
fn signing_input(
    header: &[u8],
    payload: &[u8],
    limits: Limits,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let h = base64::encoded_len(header.len(), false)?;
    let p = base64::encoded_len(payload.len(), false)?;
    let n = h
        .checked_add(1)
        .and_then(|n| n.checked_add(p))
        .ok_or(Error::Overflow)?;
    if n > limits.token_bytes || n > limits.message_bytes {
        return Err(Error::Capacity);
    }
    let mut out = buffer(n)?;
    base64::encode(header, &mut out[..h], true, false)?;
    out[h] = b'.';
    base64::encode(payload, &mut out[h + 1..], true, false)?;
    Ok(out)
}
struct TokenParts<'a> {
    signed: &'a [u8],
    signature: &'a [u8],
    payload: &'a [u8],
}
fn parts<'a>(token: &'a [u8], algorithm: &[u8], limits: Limits) -> Result<TokenParts<'a>, Error> {
    if token.len() > limits.token_bytes {
        return Err(Error::Capacity);
    }
    let first = token
        .iter()
        .position(|b| *b == b'.')
        .ok_or(Error::Malformed)?;
    let second = token[first + 1..]
        .iter()
        .position(|b| *b == b'.')
        .map(|n| n + first + 1)
        .ok_or(Error::Malformed)?;
    if token[second + 1..].contains(&b'.') {
        return Err(Error::Malformed);
    }
    let n = base64::decoded_len(&token[..first], true)?;
    if n > 1024 {
        return Err(Error::Capacity);
    }
    let mut header = buffer(n)?;
    base64::decode(&token[..first], &mut header, true)?;
    json(
        &header,
        gnunet_json::Limits {
            bytes: 1024,
            nodes: 64,
            depth: 8,
            work: 65536,
        },
        |root| {
            if !root
                .get(b"alg")
                .ok_or(Error::Malformed)?
                .string()?
                .eq_ascii(algorithm)
            {
                return Err(Error::Authentication);
            }
            if root.get(b"crit").is_some()
                || root
                    .get(b"b64")
                    .is_some_and(|v| !matches!(v.boolean(), Ok(true)))
            {
                return Err(Error::Unsupported);
            }
            Ok(())
        },
    )?;
    base64::decoded_len(&token[first + 1..second], true)?;
    base64::decoded_len(&token[second + 1..], true)?;
    Ok(TokenParts {
        signed: &token[..second],
        signature: &token[second + 1..],
        payload: &token[first + 1..second],
    })
}
fn decoded_payload<'a>(
    encoded: &[u8],
    out: &'a mut [u8],
    limits: Limits,
) -> Result<&'a [u8], Error> {
    let n = base64::decoded_len(encoded, true)?;
    if n > out.len() || n > limits.message_bytes {
        return Err(Error::Capacity);
    }
    let mut payload = buffer(n)?;
    base64::decode(encoded, &mut payload, true)?;
    validate_payload(&payload, limits)?;
    out[..n].copy_from_slice(&payload);
    Ok(&out[..n])
}
