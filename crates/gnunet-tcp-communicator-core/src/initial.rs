//! Source initial KX: representative32 plus CTR-encrypted signed confirmation136.
//! No identity is admitted to TRANSPORT before the remaining challenge/replay owner.
use crate::{
    record::Direction,
    wire::{self, Confirmation},
};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey};
use gnunet_session_crypto::{
    elligator::{self, Representative, Secret},
    exchange::{EcdhePublic, EcdheSecret},
};
use gnunet_types::Error;
use zeroize::Zeroizing;
/// The verified signed initial confirmation plus the exact consumed stream.
/// This is not a peerstore replay decision, challenge response or queue handle.
pub struct Opened {
    /// Signature-bound sender, checked against an expected outbound target when supplied.
    sender: EddsaPublicKey,
    /// Exact source sender monotonic time; replay compare/store remains pending.
    monotonic: u64,
    /// Received opaque challenge to echo at the source role-specific step.
    challenge: [u8; 32],
    direction: Direction,
}
impl Opened {
    /// Signature-bound sender; no caller mutation of this proof is exposed.
    #[must_use]
    pub const fn sender(&self) -> EddsaPublicKey {
        self.sender
    }
    /// Exact signature-bound monotonic timestamp before replay policy.
    #[must_use]
    pub const fn monotonic(&self) -> u64 {
        self.monotonic
    }
    /// Signature-bound challenge to echo at the role-specific source step.
    #[must_use]
    pub const fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
    /// Move the uniquely owned incoming cipher/MAC state after its136-byte
    /// confirmation. The clear representative did not consume CTR bytes.
    #[must_use]
    pub fn into_direction(self) -> Direction {
        self.direction
    }
}
/// Actual deterministic official0x0022 initial KX. The sender provides an owned
/// special scalar and tweak, monotonic time and independently fresh challenge.
/// Returned Direction continues at byte136; public representative bytes do not
/// consume keystream. No ordinary-KEM fallback or private field is introduced.
pub fn prepare(
    signing: &EddsaPrivateKey,
    target: EddsaPublicKey,
    ephemeral: &Secret,
    tweak: u8,
    monotonic: u64,
    challenge: &[u8; 32],
) -> Result<([u8; wire::INITIAL_KX], Direction), Error> {
    let recipient = EcdhePublic::from_edwards(target.as_bytes())?;
    let (enc, prk) = elligator::encapsulate(recipient, ephemeral, tweak)?;
    let mut direction = Direction::new(&prk)?;
    let mut c = Zeroizing::new(wire::confirmation(
        signing,
        target,
        wire::Representative(*enc.as_bytes()),
        monotonic,
        challenge,
    )?);
    direction.handshake_fragment(c.as_mut())?;
    let mut out = [0; wire::INITIAL_KX];
    out[..32].copy_from_slice(enc.as_bytes());
    out[32..].copy_from_slice(c.as_ref());
    Ok((out, direction))
}
/// Decrypt and verify one full source initial message. The caller passes the
/// source identity and matching converted private key as separate opaque owners;
/// mismatch fails before decryption. Outbound sets expected_target, while an
/// anonymous inbound protoqueue learns the signature-bound sender.
pub fn open(
    local_identity: EddsaPublicKey,
    exchange: &EcdheSecret,
    expected_target: Option<EddsaPublicKey>,
    bytes: &[u8; wire::INITIAL_KX],
) -> Result<Opened, Error> {
    if EcdhePublic::from_edwards(local_identity.as_bytes())? != exchange.public_key() {
        return Err(Error::Authentication);
    }
    let mut enc = [0; 32];
    enc.copy_from_slice(&bytes[..32]);
    let prk = elligator::decapsulate(exchange, Representative::from_bytes(enc))?;
    let mut direction = Direction::new(&prk)?;
    let mut plaintext = Zeroizing::new([0; wire::CONFIRMATION]);
    plaintext.copy_from_slice(&bytes[32..]);
    direction.handshake_fragment(plaintext.as_mut())?;
    let c = Confirmation::decode(plaintext.as_ref())?;
    c.verify(local_identity, wire::Representative(enc))?;
    if expected_target.is_some_and(|target| target != c.sender()) {
        return Err(Error::Authentication);
    }
    Ok(Opened {
        sender: c.sender(),
        monotonic: c.monotonic(),
        challenge: *c.challenge(),
        direction,
    })
}
