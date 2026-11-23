//! Fixed-layout AUTHORIZATION recovery under the original group and shared keys.
use super::{AeadKey, Body, Error, GROUP_SALT, MacChecked, Message, fmt, hkdf_gnunet, hmac512};
use gnunet_session_crypto::aead;
use gnunet_types::Error as Fault;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

fn nonce(
    identifier: &[u8; 32],
    event: &[u8; 64],
    key: &AeadKey,
) -> Result<Zeroizing<[u8; 24]>, Error> {
    let mut result = Zeroizing::new([0; 24]);
    hkdf_gnunet(
        GROUP_SALT,
        key.0.as_ref(),
        &[identifier, event],
        result.as_mut(),
    )?;
    Ok(result)
}

/// Official 192-byte AUTHORIZATION body. The detached AEAD tag is committed by
/// its HMAC; recipients reconstruct that tag using the original group key.
pub struct Authorization {
    identifier: [u8; 32],
    event: [u8; 64],
    encrypted_key: [u8; 32],
    hmac: [u8; 64],
}
impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authorization([REDACTED])")
    }
}
impl Authorization {
    /// Derive the group-key nonce, encrypt the shared key, and bind the exact
    /// ciphertext and detached tag with the transported shared key's HMAC.
    /// The caller binds the identifier/event to its admitted group state.
    /// Reusing that identifier/event under the same group key requires the same
    /// shared key; a different key would reuse the deterministic AEAD nonce.
    /// A wrapping-key/identifier/event tuple cannot encrypt a different shared
    /// key later: the nonce is deterministic for that exact tuple.
    ///
    /// # Errors
    /// Returns the actual KDF or AEAD failure, without emitting partial fields.
    pub fn seal(
        identifier: &[u8; 32],
        event: &[u8; 64],
        group_key: &AeadKey,
        shared_key: &AeadKey,
    ) -> Result<Self, Error> {
        let nonce = nonce(identifier, event, group_key)?;
        let mut ciphertext = Zeroizing::new(*shared_key.0);
        let tag = Zeroizing::new(aead::xchacha20poly1305_seal(
            &group_key.0,
            &nonce,
            &[],
            ciphertext.as_mut(),
        )?);
        let mut auth = Zeroizing::new([0; 64]);
        hkdf_gnunet(
            GROUP_SALT,
            shared_key.0.as_ref(),
            &[identifier, event],
            auth.as_mut(),
        )?;
        let hmac = hmac512(
            auth.as_ref(),
            &[identifier, event, ciphertext.as_ref(), tag.as_ref()],
        );
        Ok(Self {
            identifier: *identifier,
            event: *event,
            encrypted_key: *ciphertext,
            hmac,
        })
    }
    /// Exact transmitted fields; no detached tag or private extension is added.
    pub fn body(&self) -> Body<'_> {
        Body::Authorization {
            identifier: &self.identifier,
            event: &self.event,
            encrypted_key: &self.encrypted_key,
            hmac: &self.hmac,
        }
    }
}

/// Reconstruct the producer's ciphertext and detached tag and compare both its
/// ciphertext and carried HMAC in constant time. This authenticates the original
/// body under the two supplied keys, not its room, member or epoch authority.
///
/// # Errors
/// Rejects another message kind, an incorrect key or any changed body field.
pub fn verify_authorization<'a>(
    message: Message<'a>,
    group_key: &AeadKey,
    shared_key: &AeadKey,
) -> Result<MacChecked<'a>, Error> {
    let Body::Authorization {
        identifier,
        event,
        encrypted_key,
        hmac,
    } = message.body()
    else {
        return Err(Fault::InvalidInput.into());
    };
    let actual = Authorization::seal(identifier, event, group_key, shared_key)?;
    let matches = actual.encrypted_key.ct_eq(encrypted_key) & actual.hmac.ct_eq(hmac);
    if !bool::from(matches) {
        return Err(Fault::Authentication.into());
    }
    Ok(MacChecked { message })
}

/// Recover the candidate shared key from the original group-key stream, then
/// reconstruct and check the producer's ciphertext/tag/HMAC before releasing
/// that zeroizing key. No candidate bytes escape on any failure path.
///
/// The omitted detached tag is deterministic from the group key, nonce and
/// ciphertext. The carried HMAC commits to that exact tag under the transported
/// key; it supplies the body authentication checked here. Sender signature and
/// group/event authorization remain with the caller.
///
/// # Errors
/// Rejects other message kinds and any key or body authentication mismatch.
pub fn open_authorization(message: Message<'_>, group_key: &AeadKey) -> Result<AeadKey, Error> {
    let Body::Authorization {
        identifier,
        event,
        encrypted_key,
        ..
    } = message.body()
    else {
        return Err(Fault::InvalidInput.into());
    };
    let nonce = nonce(identifier, event, group_key)?;
    let mut candidate = Zeroizing::new(*encrypted_key);
    // Applying the same ChaCha stream reverses its XOR. This call's tag is not
    // authentication evidence; the complete original HMAC is checked below.
    let _candidate_tag = Zeroizing::new(aead::xchacha20poly1305_seal(
        &group_key.0,
        &nonce,
        &[],
        candidate.as_mut(),
    )?);
    let key = AeadKey::from_bytes(*candidate);
    verify_authorization(message, group_key, &key)?;
    Ok(key)
}
