//! One native activation offer bound to its original supervised launch.

use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature};
use gnunet_native::socket_activation::BootstrapGrant;
use std::io;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"GNUNET-RS/activation/grant/v1\0";
const SID_BYTES: usize = 68;
const PAYLOAD: usize = 4 + 8 + 1 + SID_BYTES;
const SIGNED: usize = DOMAIN.len() + PAYLOAD;
const SIGNATURE: usize = 64;
pub(super) const LENGTH: usize = SIGNED + SIGNATURE;

pub(super) struct Signer(EddsaPrivateKey);

impl Signer {
    pub(super) fn generate() -> io::Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        gnunet_native::entropy::fill(seed.as_mut())?;
        Ok(Self(EddsaPrivateKey::from_seed(*seed)))
    }

    pub(super) fn verifying_key(&self) -> [u8; 32] {
        *self.0.public_key().as_bytes()
    }

    pub(super) fn seal(self, grant: BootstrapGrant) -> io::Result<SignedGrant> {
        self.frame(
            grant.recipient_pid(),
            grant.target_handle(),
            grant.publisher().as_bytes(),
        )
    }

    fn frame(self, recipient: u32, handle: u64, publisher: &[u8]) -> io::Result<SignedGrant> {
        if recipient == 0 || handle == 0 || publisher.is_empty() || publisher.len() > SID_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut frame = [0; LENGTH];
        let (body, signature) = frame.split_at_mut(SIGNED);
        let (domain, payload) = body.split_at_mut(DOMAIN.len());
        domain.copy_from_slice(DOMAIN);
        payload[..4].copy_from_slice(&recipient.to_le_bytes());
        payload[4..12].copy_from_slice(&handle.to_le_bytes());
        payload[12] = publisher.len() as u8;
        payload[13..13 + publisher.len()].copy_from_slice(publisher);
        signature.copy_from_slice(self.0.sign_raw(body).as_bytes());
        Ok(SignedGrant(frame))
    }
}

pub(super) struct SignedGrant([u8; LENGTH]);

impl SignedGrant {
    pub(super) fn bytes(&self) -> &[u8; LENGTH] {
        &self.0
    }
}

pub(super) struct Verifier(EddsaPublicKey);

impl Verifier {
    pub(super) fn parse(hex: &str) -> io::Result<Self> {
        if hex.len() != 64 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut key = [0; 32];
        for (byte, &[high, low]) in key.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
            *byte = (digit(high)? << 4) | digit(low)?;
        }
        Ok(Self(EddsaPublicKey::from_bytes(key)))
    }

    pub(super) fn verify(self, frame: &[u8; LENGTH], recipient: u32) -> io::Result<(usize, &[u8])> {
        let (body, signature) = frame.split_at(SIGNED);
        let signature = signature
            .first_chunk::<SIGNATURE>()
            .ok_or(io::ErrorKind::InvalidData)?;
        self.0
            .verify_message(body, &EddsaSignature::from_bytes(*signature))
            .map_err(|_| io::ErrorKind::PermissionDenied)?;
        let payload = body
            .strip_prefix(DOMAIN)
            .ok_or(io::ErrorKind::InvalidData)?;
        if payload[..4] != recipient.to_le_bytes() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let raw = u64::from_le_bytes(
            payload[4..12]
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
        );
        let length = usize::from(payload[12]);
        if raw == 0 || length == 0 || length > SID_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (publisher, padding) = payload[13..].split_at(length);
        if padding.iter().any(|&byte| byte != 0) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let handle = usize::try_from(raw).map_err(|_| io::ErrorKind::InvalidData)?;
        Ok((handle, publisher))
    }
}

fn digit(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(io::ErrorKind::InvalidInput.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_binds_the_exact_launch_recipient_and_capability() -> io::Result<()> {
        let signer = Signer(EddsaPrivateKey::from_seed([0x21; 32]));
        let key = signer.verifying_key();
        let verify = || Verifier(EddsaPublicKey::from_bytes(key));
        let signed = signer.frame(23, 57, b"publisher")?;
        if verify().verify(signed.bytes(), 23)? != (57, &b"publisher"[..])
            || verify().verify(signed.bytes(), 24).is_ok()
        {
            return Err(io::Error::other("recipient or capability lost"));
        }
        let mut tampered = *signed.bytes();
        tampered[DOMAIN.len() + 4] ^= 1;
        if verify().verify(&tampered, 23).is_ok()
            || Verifier(EddsaPublicKey::from_bytes([0; 32]))
                .verify(signed.bytes(), 23)
                .is_ok()
        {
            return Err(io::Error::other("unauthenticated activation capability"));
        }
        Ok(())
    }
}
