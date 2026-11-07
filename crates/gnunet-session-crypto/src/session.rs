//! Exact v0.29.1 CAKE and communicator KDF contexts; no handshake state machine.
use crate::{Prk, hkdf_extract, kdf::hmac512};
use gnunet_types::Error;
use zeroize::Zeroizing;
/// Which official participant's traffic/Finished context is derived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Initiator labels start with `i`.
    Initiator,
    /// Responder labels start with `r`.
    Responder,
}
/// An owner-held cipher key and its per-message public nonce.
pub struct AeadMaterial {
    pub(crate) key: Zeroizing<[u8; 32]>,
    nonce: [u8; 24],
}
impl AeadMaterial {
    /// Per-record nonce after the source-exact BE64 sequence XOR.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }
    /// Encrypt in place and return the detached official16-byte tag.
    pub fn seal(&self, aad: &[u8], bytes: &mut [u8]) -> Result<[u8; 16], Error> {
        crate::aead::xchacha20poly1305_seal(&self.key, &self.nonce, aad, bytes)
    }
    /// Verify before releasing plaintext; authentication failure erases bytes.
    pub fn open(&self, aad: &[u8], bytes: &mut [u8], tag: &[u8; 16]) -> Result<(), Error> {
        crate::aead::xchacha20poly1305_open(&self.key, &self.nonce, aad, bytes, tag)
    }
}
/// Extract the CAKE early secret and expand ETS using the64-byte transcript hash.
pub fn early(shared: &Prk, transcript: &[u8; 64]) -> Result<(Prk, Prk), Error> {
    let es = hkdf_extract(&[], &[shared.0.as_ref()]);
    let ets = es.derive(&[b"cake10", b"early data", transcript])?;
    Ok((es, ets))
}
/// CAKE HS = Extract(Expand(ES,cake10||derived), shared_ephemeral).
pub fn handshake(es: &Prk, shared_ephemeral: &Prk) -> Result<Prk, Error> {
    let derived = es.derive(&[b"cake10", b"derived"])?;
    Ok(hkdf_extract(
        derived.0.as_ref(),
        &[shared_ephemeral.0.as_ref()],
    ))
}
/// IHTS/RHTS with the original raw SHA512 transcript bytes.
pub fn handshake_traffic(hs: &Prk, transcript: &[u8; 64], role: Role) -> Result<Prk, Error> {
    hs.derive(&[
        b"cake10",
        match role {
            Role::Initiator => b"i hs traffic",
            Role::Responder => b"r hs traffic",
        },
        transcript,
    ])
}
/// CAKE MS = Extract(Expand(HS,cake10||derived), shared_initiator).
pub fn master(hs: &Prk, shared_initiator: &Prk) -> Result<Prk, Error> {
    let derived = hs.derive(&[b"cake10", b"derived"])?;
    Ok(hkdf_extract(
        derived.0.as_ref(),
        &[shared_initiator.0.as_ref()],
    ))
}
/// IATS/RATS initial application traffic with role-specific official context.
pub fn application_traffic(ms: &Prk, transcript: &[u8; 64], role: Role) -> Result<Prk, Error> {
    ms.derive(&[
        b"cake10",
        match role {
            Role::Initiator => b"i ap traffic",
            Role::Responder => b"r ap traffic",
        },
        transcript,
    ])
}
/// Advance only the secret bytes; epochs/replay/sequence authority belong to CORE.
pub fn next_application(old: &Prk) -> Result<Prk, Error> {
    old.derive(&[b"cake10", b"traffic upd"])
}
/// Finished is HMAC-SHA512 over transcript with a64-byte role-derived key.
pub fn finished(ms: &Prk, transcript: &[u8; 64], role: Role) -> Result<[u8; 64], Error> {
    let mut key = Zeroizing::new([0; 64]);
    ms.expand(
        &[
            b"cake10",
            match role {
                Role::Initiator => b"i finished",
                Role::Responder => b"r finished",
            },
        ],
        key.as_mut(),
    )?;
    Ok(*hmac512(key.as_ref(), &[transcript]))
}
/// Derive key32 and nonce24, then XOR sequence BE64 into the last8 nonce bytes.
/// Callers must enforce official epochs, monotonic sequence and replay policy.
pub fn record_material(traffic: &Prk, seq: u64) -> Result<AeadMaterial, Error> {
    let mut key = Zeroizing::new([0; 32]);
    let mut nonce = [0; 24];
    traffic.expand(&[b"cake10", b"key"], key.as_mut())?;
    traffic.expand(&[b"cake10", b"iv"], &mut nonce)?;
    for (byte, sequence) in nonce[16..].iter_mut().zip(seq.to_be_bytes()) {
        *byte ^= sequence;
    }
    Ok(AeadMaterial { key, nonce })
}
/// Expand the independent CAKE record sequence-number protection bytes.
pub fn sequence_protection(secret: &Prk, output: &mut [u8]) -> Result<(), Error> {
    secret.expand(&[b"cake10", b"sn"], output)
}
/// Official TCP communicator key32, AES counter16 and HMAC key64; erased on drop.
pub struct TcpMaterial {
    pub(crate) key: Zeroizing<[u8; 32]>,
    pub(crate) counter: Zeroizing<[u8; 16]>,
    pub(crate) hmac: Zeroizing<[u8; 64]>,
}
/// Exactly the TCP labels; no frame authentication or stream position is invented.
pub fn tcp_material(secret: &Prk) -> Result<TcpMaterial, Error> {
    let mut key = Zeroizing::new([0; 32]);
    let mut counter = Zeroizing::new([0; 16]);
    let mut hmac = Zeroizing::new([0; 64]);
    secret.expand(&[b"gnunet-communicator-tcp-key"], key.as_mut())?;
    secret.expand(&[b"gnunet-communicator-tcp-ctr"], counter.as_mut())?;
    secret.expand(&[b"gnunet-communicator-hmac"], hmac.as_mut())?;
    Ok(TcpMaterial { key, counter, hmac })
}
/// Persistent official TCP AES256CTR position and its independent HMAC key.
pub struct TcpStream {
    cipher: ctr::Ctr128BE<aes::Aes256>,
    hmac: Zeroizing<[u8; 64]>,
}
impl TcpMaterial {
    /// Transfer the keys into one persistent stream; secret material is erased
    /// when this owner and its cipher state are dropped.
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        use aes::cipher::KeyIvInit;
        TcpStream {
            cipher: ctr::Ctr128BE::<aes::Aes256>::new((&*self.key).into(), (&*self.counter).into()),
            hmac: self.hmac,
        }
    }
}
impl TcpStream {
    /// Encrypt/decrypt the next ordered stream bytes, retaining partial blocks.
    /// Counter exhaustion erases the rejected range; no protocol frame is added.
    pub fn crypt(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        use aes::cipher::StreamCipher;
        use zeroize::Zeroize;
        self.cipher.try_apply_keystream(bytes).map_err(|_| {
            bytes.zeroize();
            Error::TooLarge
        })
    }
    /// Official TCP calculate_hmac: truncate SHA512 HMAC to32 bytes, then
    /// replace the sole64-byte MAC key with SHA512(oldkey). The old owner is
    /// erased at replacement; no initial key copy is kept after ratcheting.
    #[must_use]
    pub fn hmac_ratchet(&mut self, parts: &[&[u8]]) -> [u8; 32] {
        let full = hmac512(self.hmac.as_ref(), parts);
        let mut tag = [0; 32];
        tag.copy_from_slice(&full[..32]);
        self.hmac = Zeroizing::new(gnunet_crypto::hash512(self.hmac.as_ref()));
        tag
    }
    /// Standard HMAC-SHA512 with the official derived64-byte key.
    #[must_use]
    pub fn hmac(&self, parts: &[&[u8]]) -> [u8; 64] {
        *hmac512(self.hmac.as_ref(), parts)
    }
}
/// Official UDP communicator IV width: AES_IV_SIZE=(96/8).
pub const UDP_IV_BYTES: usize = 12;

/// Complete UDP key32/IV12 KDF only. The separate payload cipher is AES-GCM,
/// which is not implemented by this function; it is never replaced with CTR.
/// The caller must erase both output key buffers when their ownership ends.
pub fn udp_key_iv(
    secret: &Prk,
    serial: u32,
    key: &mut [u8; 32],
    iv: &mut [u8; UDP_IV_BYTES],
) -> Result<(), Error> {
    let serial = serial.to_be_bytes();
    secret.expand(&[b"gnunet-communicator-udp-key", &serial], key)?;
    secret.expand(&[b"gnunet-communicator-udp-iv", &serial], iv)
}
/// Official KID: Extract(serialBE32,master) then expand the UDP KID context.
pub fn udp_key_id(secret: &Prk, serial: u32) -> Result<[u8; 32], Error> {
    let serial = serial.to_be_bytes();
    let prk = hkdf_extract(&serial, &[secret.0.as_ref()]);
    let mut id = [0; 32];
    prk.expand(&[b"gnunet-communicator-udp-kid"], &mut id)?;
    Ok(id)
}
/// Official64-byte key acknowledgement marker (not a payload MAC algorithm).
pub fn udp_cmac(secret: &Prk) -> Result<[u8; 64], Error> {
    let mut cmac = [0; 64];
    secret.expand(&[b"gnunet-communicator-udp-cmac"], &mut cmac)?;
    Ok(cmac)
}
/// Apply the source CAKE sequence-number mask (the same operation unprotects).
/// `sequence` is exactly eight wire bytes. The public tag's first four bytes
/// select a big-endian ChaCha block counter; its last twelve form the nonce.
/// The independently expanded `cake10||sn` key is32 bytes. No replay admission
/// or authentication is implied by obtaining a numeric sequence this way.
pub fn protect_sequence(
    traffic: &Prk,
    tag: &[u8; 16],
    sequence: &[u8; 8],
) -> Result<[u8; 8], Error> {
    use chacha20::{ChaChaCore, R20, variants::Ietf};
    use cipher::{KeyIvInit, StreamCipherCore};
    let mut key = Zeroizing::new([0; 32]);
    sequence_protection(traffic, key.as_mut())?;
    let mut nonce = [0; 12];
    nonce.copy_from_slice(&tag[4..]);
    let mut core = ChaChaCore::<R20, Ietf>::new((&*key).into(), (&nonce).into());
    core.set_block_pos(u32::from_be_bytes([tag[0], tag[1], tag[2], tag[3]]));
    let mut mask = Zeroizing::new([0; 64]);
    core.write_keystream_block((&mut *mask).into());
    let mut out = *sequence;
    for (byte, mask) in out.iter_mut().zip(mask.iter()) {
        *byte ^= *mask;
    }
    Ok(out)
}
/// Protect one current-source CAKE payload with empty associated data, returning
/// `(detached_tag, protected_sequence_BE64)`. Epoch/header framing, sequence
/// uniqueness and association/rekey checks remain the protocol owner's duty.
pub fn seal_record(
    traffic: &Prk,
    sequence: u64,
    bytes: &mut [u8],
) -> Result<([u8; 16], [u8; 8]), Error> {
    let material = record_material(traffic, sequence)?;
    let tag = material.seal(&[], bytes)?;
    Ok((
        tag,
        protect_sequence(traffic, &tag, &sequence.to_be_bytes())?,
    ))
}
/// Unmask the record sequence, authenticate with source-empty associated data,
/// then return the authenticated numeric sequence. Failed authentication erases
/// the entire mutable range; this helper never commits a replay window or epoch.
pub fn open_record(
    traffic: &Prk,
    tag: &[u8; 16],
    protected_sequence: &[u8; 8],
    bytes: &mut [u8],
) -> Result<u64, Error> {
    let sequence = u64::from_be_bytes(protect_sequence(traffic, tag, protected_sequence)?);
    record_material(traffic, sequence)?.open(&[], bytes, tag)?;
    Ok(sequence)
}
#[cfg(test)]
mod tcp_ratchet_tests {
    //! The persistent cipher owns only its current source MAC key.
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Private actual-key-owner fixture asserts each source ratchet replacement"
    )]
    fn ratchet_replaces_the_single_key_and_truncates_each_full_mac() -> Result<(), Error> {
        let secret = Prk::from_bytes([42; 32]);
        let mut stream = tcp_material(&secret)?.into_stream();
        let original = Zeroizing::new(*stream.hmac);
        let full = hmac512(original.as_ref(), &[b"message"]);
        let tag = stream.hmac_ratchet(&[b"mes", b"sage"]);
        assert_eq!(&tag, &full[..32]);
        let next = Zeroizing::new(gnunet_crypto::hash512(original.as_ref()));
        assert_eq!(stream.hmac.as_ref(), next.as_ref());
        let full = hmac512(next.as_ref(), &[b"next"]);
        assert_eq!(&stream.hmac_ratchet(&[b"next"]), &full[..32]);
        assert_eq!(stream.hmac.as_ref(), gnunet_crypto::hash512(next.as_ref()));
        Ok(())
    }
}
