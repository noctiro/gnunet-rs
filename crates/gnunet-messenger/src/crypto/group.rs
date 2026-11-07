//! Actual key-derived HMAC-SHA512 and ACCESS HPKE composition. The caller must
//! bind the supplied key/event/identifier to its authorized original epoch state.
use super::{AeadKey, EcdhePublic, EcdheSecret, Entropy, Error};
use crate::wire::{body::Body, message::Message};
use core::fmt;
use gnunet_crypto::hkdf_gnunet;
use gnunet_session_crypto::{hpke, transcript::hmac512};
use gnunet_types::Error as Fault;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
/// Actual C sizeof(string) salt, including its final NUL.
pub const ANNOUNCEMENT_SALT: &[u8] = b"gnunet-messenger-announcement-key-k*d-p!80\0";
/// Actual C sizeof(string) salt, including its final NUL.
pub const EPOCH_SALT: &[u8] = b"gnunet-messenger-epoch-key-ePGN3bGR-}*i$<2\0";
/// Actual C sizeof(string) salt, including its final NUL.
pub const GROUP_SALT: &[u8] = b"gnunet-messenger-group-key-L)&7{4i(WSEPpR-\0";
/// Actual HPKE application info strlen bytes; no trailing NUL.
pub const HPKE_INFO: &[u8] = b"messenger";
/// Compute the exact active HMAC for ANNOUNCEMENT, ACCESS or REVOLUTION.
/// Fixed field concatenation equals their actual C struct prefix, including
/// the original BE8 timeout bytes. It excludes the final HMAC64. No portable
/// wire hash is silently substituted for the official independent body coverage.
/// AUTHORIZATION fails because its actual wire has no required separate MAC16.
pub fn message_mac(body: Body<'_>, key: &AeadKey) -> Result<[u8; 64], Error> {
    let mut auth = Zeroizing::new([0; 64]);
    match body {
        Body::Announcement {
            identifier,
            public_key,
            nonce,
            timeout,
            ..
        } => {
            hkdf_gnunet(
                ANNOUNCEMENT_SALT,
                key.0.as_ref(),
                &[identifier, nonce],
                auth.as_mut(),
            )?;
            Ok(hmac512(
                auth.as_ref(),
                &[identifier, public_key, nonce, &timeout.to_be_bytes()],
            ))
        }
        Body::Access {
            event,
            encrypted_key,
            ..
        } => {
            hkdf_gnunet(EPOCH_SALT, key.0.as_ref(), &[event], auth.as_mut())?;
            Ok(hmac512(auth.as_ref(), &[event, encrypted_key]))
        }
        Body::Revolution {
            identifier, nonce, ..
        } => {
            hkdf_gnunet(
                ANNOUNCEMENT_SALT,
                key.0.as_ref(),
                &[identifier, nonce],
                auth.as_mut(),
            )?;
            Ok(hmac512(auth.as_ref(), &[identifier, nonce]))
        }
        Body::Authorization { .. } => Err(Error::AuthorizationMacOmitted),
        _ => Err(Fault::InvalidInput.into()),
    }
}
/// Sealed actual HMAC check under one explicitly caller-selected key. It does
/// not authorize an epoch transition, sender signature, room or event linkage.
pub struct MacChecked<'a> {
    message: Message<'a>,
}
impl fmt::Debug for MacChecked<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MacChecked([REDACTED], epoch authorization pending)")
    }
}
impl<'a> MacChecked<'a> {
    /// Immutable original message whose actual body HMAC passed.
    pub const fn message(&self) -> Message<'a> {
        self.message
    }
}
/// Derive and verify the actual carried body HMAC in constant time. Missing
/// authorization MAC fails explicitly; no default zero or Verified event exists.
pub fn verify_mac<'a>(message: Message<'a>, key: &AeadKey) -> Result<MacChecked<'a>, Error> {
    let body = message.body();
    let expected = match body {
        Body::Announcement { hmac, .. }
        | Body::Access { hmac, .. }
        | Body::Revolution { hmac, .. } => hmac,
        Body::Authorization { .. } => return Err(Error::AuthorizationMacOmitted),
        _ => return Err(Fault::InvalidInput.into()),
    };
    let computed = message_mac(body, key)?;
    if !bool::from(computed.ct_eq(expected)) {
        return Err(Fault::Authentication.into());
    }
    Ok(MacChecked { message })
}
/// Real outgoing ACCESS ciphertext80 and its HMAC64. This contains no plaintext
/// shared key, has no fake receipt, and can be borrowed by the exact body codec.
pub struct Access {
    event: [u8; 64],
    encrypted_key: [u8; 80],
    hmac: [u8; 64],
}
impl fmt::Debug for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Access([REDACTED])")
    }
}
impl Access {
    /// Perform actual Base HPKE with info="messenger"/empty AAD, then calculate
    /// the active ACCESS HMAC using the very shared key being transported.
    pub fn seal(
        event: &[u8; 64],
        recipient: EcdhePublic,
        key: &AeadKey,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        let mut result = Self {
            event: *event,
            encrypted_key: [0; 80],
            hmac: [0; 64],
        };
        let lengths = hpke::seal_oneshot(
            recipient,
            HPKE_INFO,
            &[],
            key.0.as_ref(),
            &mut result.encrypted_key,
            entropy,
        )?;
        if lengths.total_written != result.encrypted_key.len() {
            return Err(Fault::Conflict.into());
        }
        result.hmac = message_mac(result.body(), key)?;
        Ok(result)
    }
    /// Exact original208-byte active body fields; outer signature is separate.
    pub fn body(&self) -> Body<'_> {
        Body::Access {
            event: &self.event,
            encrypted_key: &self.encrypted_key,
            hmac: &self.hmac,
        }
    }
}
/// Actually HPKE-open an original ACCESS, then verify its HMAC under the newly
/// recovered key before releasing that zeroizing capability. Caller must still
/// authorize the event, recipient and epoch in actual room state.
pub fn open_access(message: Message<'_>, recipient: &EcdheSecret) -> Result<AeadKey, Error> {
    let Body::Access { encrypted_key, .. } = message.body() else {
        return Err(Fault::InvalidInput.into());
    };
    let mut raw = Zeroizing::new([0; 32]);
    let n = hpke::open_oneshot(recipient, HPKE_INFO, &[], encrypted_key, raw.as_mut())?;
    if n != raw.len() {
        return Err(Fault::Malformed.into());
    }
    let key = AeadKey::from_bytes(*raw);
    verify_mac(message, &key)?;
    Ok(key)
}
/// Actual outgoing AUTHORIZATION producer. The generated MAC is used locally
/// in its HMAC calculation, then omitted by the official192-byte body codec.
/// This mirrors the active producer but cannot make the receiver recover that
/// absent MAC. It conveys no interoperable key-recovery or Verified guarantee.
pub struct Authorization {
    identifier: [u8; 32],
    event: [u8; 64],
    encrypted_key: [u8; 32],
    hmac: [u8; 64],
}
impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authorization([REDACTED], official MAC omission)")
    }
}
impl Authorization {
    /// Execute the actual C producer's nonce KDF, group-key AEAD and transported
    /// shared-key HMAC. The original event/identifier must be unique and admitted
    /// by the caller's group state. No missing received MAC is defaulted to zero.
    pub fn seal(
        identifier: &[u8; 32],
        event: &[u8; 64],
        group_key: &AeadKey,
        shared_key: &AeadKey,
    ) -> Result<Self, Error> {
        let mut nonce = Zeroizing::new([0; 24]);
        hkdf_gnunet(
            GROUP_SALT,
            group_key.0.as_ref(),
            &[identifier, event],
            nonce.as_mut(),
        )?;
        let mut ciphertext = Zeroizing::new(*shared_key.0);
        let actual_mac = gnunet_session_crypto::aead::xchacha20poly1305_seal(
            &group_key.0,
            &nonce,
            &[],
            ciphertext.as_mut(),
        )?;
        let mut auth = Zeroizing::new([0; 64]);
        // The actual producer signs using the transported new shared key,
        // independently of the group key that encrypted that shared key.
        hkdf_gnunet(
            GROUP_SALT,
            shared_key.0.as_ref(),
            &[identifier, event],
            auth.as_mut(),
        )?;
        let hmac = hmac512(
            auth.as_ref(),
            &[identifier, event, ciphertext.as_ref(), &actual_mac],
        );
        Ok(Self {
            identifier: *identifier,
            event: *event,
            encrypted_key: *ciphertext,
            hmac,
        })
    }
    /// Exact192-byte transmitted fields. The discarded actual MAC cannot be
    /// recovered from this view and no private wire extension is appended.
    pub fn body(&self) -> Body<'_> {
        Body::Authorization {
            identifier: &self.identifier,
            event: &self.event,
            encrypted_key: &self.encrypted_key,
            hmac: &self.hmac,
        }
    }
}
