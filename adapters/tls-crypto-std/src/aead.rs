//! TLS records and QUIC packet protection backed by RustCrypto AEADs.

use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20::{ChaChaCore, R20, variants::Ietf};
use chacha20poly1305::ChaCha20Poly1305;
use cipher::{
    BlockCipherEncrypt, KeyIvInit, StreamCipherCore,
    consts::{U12, U16},
};
use rustls::{
    ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion,
    crypto::cipher::{
        AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
        MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
        Tls12AeadAlgorithm, Tls13AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
        make_tls13_aad,
    },
    quic,
};
use zeroize::Zeroizing;

const TAG_LEN: usize = 16;
const EXPLICIT_LEN: usize = 8;
const GCM_SALT_LEN: usize = 4;
const MAX_FRAGMENT: usize = 1 << 14;
const MAX_TLS13_CIPHERTEXT: usize = MAX_FRAGMENT + 256;
const MAX_QUIC_PACKET_NUMBER: u64 = (1 << 62) - 1;

pub(crate) static AES128_GCM: Algorithm = Algorithm::Aes128;
pub(crate) static AES256_GCM: Algorithm = Algorithm::Aes256;
pub(crate) static CHACHA20_POLY1305: Algorithm = Algorithm::Chacha20;

#[derive(Clone, Copy)]
pub(crate) enum Algorithm {
    Aes128,
    Aes256,
    Chacha20,
}

impl Algorithm {
    const fn key_size(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 | Self::Chacha20 => 32,
        }
    }

    const fn framing12(self) -> Framing {
        match self {
            Self::Aes128 | Self::Aes256 => Framing::Tls12Gcm,
            Self::Chacha20 => Framing::Tls12Chacha,
        }
    }

    fn tls12_iv(self, fixed: &[u8], explicit: Option<&[u8]>) -> Option<Iv> {
        if matches!(self.framing12(), Framing::Tls12Gcm) {
            let salt = <&[u8; GCM_SALT_LEN]>::try_from(fixed).ok()?;
            let mut iv = [0; 12];
            iv[..GCM_SALT_LEN].copy_from_slice(salt);
            if let Some(offset) = explicit {
                iv[GCM_SALT_LEN..].copy_from_slice(<&[u8; EXPLICIT_LEN]>::try_from(offset).ok()?);
            }
            Some(Iv::from(iv))
        } else if explicit.is_none_or(<[u8]>::is_empty) {
            Some(Iv::from(<[u8; 12]>::try_from(fixed).ok()?))
        } else {
            None
        }
    }

    fn record_encrypter(
        self,
        key: &AeadKey,
        iv: Option<Iv>,
        framing: Framing,
    ) -> Box<dyn MessageEncrypter> {
        match self {
            Self::Aes128 => Box::new(RecordKey::<Aes128Gcm>::new(key, iv, framing)),
            Self::Aes256 => Box::new(RecordKey::<Aes256Gcm>::new(key, iv, framing)),
            Self::Chacha20 => Box::new(RecordKey::<ChaCha20Poly1305>::new(key, iv, framing)),
        }
    }

    fn record_decrypter(
        self,
        key: &AeadKey,
        iv: Option<Iv>,
        framing: Framing,
    ) -> Box<dyn MessageDecrypter> {
        match self {
            Self::Aes128 => Box::new(RecordKey::<Aes128Gcm>::new(key, iv, framing)),
            Self::Aes256 => Box::new(RecordKey::<Aes256Gcm>::new(key, iv, framing)),
            Self::Chacha20 => Box::new(RecordKey::<ChaCha20Poly1305>::new(key, iv, framing)),
        }
    }

    fn traffic_secrets(
        self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        if key.as_ref().len() != self.key_size() {
            return Err(UnsupportedOperationError);
        }
        Ok(match self {
            Self::Aes128 => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Self::Aes256 => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Self::Chacha20 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        })
    }
}

impl Tls13AeadAlgorithm for Algorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.record_encrypter(&key, Some(iv), Framing::Tls13)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.record_decrypter(&key, Some(iv), Framing::Tls13)
    }

    fn key_len(&self) -> usize {
        self.key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        self.traffic_secrets(key, iv)
    }
}

impl Tls12AeadAlgorithm for Algorithm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        self.record_encrypter(&key, self.tls12_iv(iv, Some(extra)), self.framing12())
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        self.record_decrypter(&key, self.tls12_iv(iv, None), self.framing12())
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        let explicit_nonce_len = self.framing12().prefix_len();
        KeyBlockShape {
            enc_key_len: self.key_size(),
            fixed_iv_len: 12 - explicit_nonce_len,
            explicit_nonce_len,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv = self
            .tls12_iv(iv, Some(explicit))
            .ok_or(UnsupportedOperationError)?;
        self.traffic_secrets(key, iv)
    }
}

#[derive(Clone, Copy)]
enum Framing {
    Tls13,
    Tls12Gcm,
    Tls12Chacha,
}

impl Framing {
    const fn prefix_len(self) -> usize {
        match self {
            Self::Tls12Gcm => EXPLICIT_LEN,
            Self::Tls12Chacha | Self::Tls13 => 0,
        }
    }

    const fn overhead(self) -> usize {
        match self {
            Self::Tls13 => TAG_LEN + 1,
            _ => TAG_LEN + self.prefix_len(),
        }
    }
}

trait TlsCipher: AeadInOut<NonceSize = U12, TagSize = U16> + KeyInit + Send + Sync + 'static {}
impl<T> TlsCipher for T where
    T: AeadInOut<NonceSize = U12, TagSize = U16> + KeyInit + Send + Sync + 'static
{
}

struct RecordKey<K> {
    // Rustls constructors cannot return a key-setup error. Invalid dimensions
    // produce an unusable record key rather than a panic or default key.
    material: Option<(K, Iv)>,
    framing: Framing,
}

impl<K: TlsCipher> RecordKey<K> {
    fn new(key: &AeadKey, iv: Option<Iv>, framing: Framing) -> Self {
        Self {
            material: iv.and_then(|iv| K::new_from_slice(key.as_ref()).ok().map(|key| (key, iv))),
            framing,
        }
    }
}

impl<K: TlsCipher> MessageEncrypter for RecordKey<K> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let (key, iv) = self.material.as_ref().ok_or(Error::EncryptError)?;
        let plain_len = msg.payload.len();
        if plain_len > MAX_FRAGMENT {
            return Err(Error::EncryptError);
        }
        let total_len = self.encrypted_payload_len(plain_len);
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let nonce = Nonce::new(iv, seq).0;

        // TLS 1.2 GCM carries the low eight bytes of its nonce on the wire.
        let prefix = self.framing.prefix_len();
        if prefix != 0 {
            payload.extend_from_slice(&nonce[GCM_SALT_LEN..]);
        }
        payload.extend_from_chunks(&msg.payload);

        let (typ, version, tag) = if matches!(self.framing, Framing::Tls13) {
            payload.extend_from_slice(&[msg.typ.into()]);
            let aad = make_tls13_aad(total_len);
            let tag = seal(key, &nonce, &aad, payload.as_mut())?;
            (ContentType::ApplicationData, ProtocolVersion::TLSv1_2, tag)
        } else {
            let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
            let tag = seal(key, &nonce, &aad, &mut payload.as_mut()[prefix..])?;
            (msg.typ, msg.version, tag)
        };
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(typ, version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len.saturating_add(self.framing.overhead())
    }
}

impl<K: TlsCipher> MessageDecrypter for RecordKey<K> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let (key, iv) = self.material.as_ref().ok_or(Error::DecryptError)?;
        let prefix = self.framing.prefix_len();
        let total_len = msg.payload.len();
        let end = total_len
            .checked_sub(TAG_LEN)
            .filter(|end| *end >= prefix)
            .ok_or(Error::DecryptError)?;

        if matches!(self.framing, Framing::Tls13) {
            if total_len > MAX_TLS13_CIPHERTEXT {
                return Err(Error::PeerSentOversizedRecord);
            }
            let nonce = Nonce::new(iv, seq).0;
            let aad = make_tls13_aad(total_len);
            open(key, &nonce, &aad, &mut msg.payload)?;
            msg.payload.truncate(end);
            return msg.into_tls13_unpadded_message();
        }

        let plain_len = end - prefix;
        if plain_len > MAX_FRAGMENT {
            return Err(Error::PeerSentOversizedRecord);
        }
        let nonce = if prefix == 0 {
            Nonce::new(iv, seq).0
        } else {
            let mut nonce = [0; 12];
            nonce[..GCM_SALT_LEN].copy_from_slice(&iv.as_ref()[..GCM_SALT_LEN]);
            nonce[GCM_SALT_LEN..].copy_from_slice(&msg.payload[..prefix]);
            nonce
        };
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        open(key, &nonce, &aad, &mut msg.payload[prefix..])?;
        Ok(msg.into_plain_message_range(prefix..end))
    }
}

fn seal<K: TlsCipher>(
    key: &K,
    nonce: &[u8; 12],
    aad: &[u8],
    payload: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    key.encrypt_inout_detached(nonce.into(), aad, payload.into())
        .map(Into::into)
        .map_err(|_| Error::EncryptError)
}

fn open<'a, K: TlsCipher>(
    key: &K,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let plain_len = ciphertext
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(Error::DecryptError)?;
    let (payload, tag) = ciphertext.split_at_mut(plain_len);
    let tag = <&[u8; TAG_LEN]>::try_from(&*tag).map_err(|_| Error::DecryptError)?;
    key.decrypt_inout_detached(nonce.into(), aad, (&mut *payload).into(), tag.into())
        .map_err(|_| Error::DecryptError)?;
    Ok(payload)
}

impl quic::Algorithm for Algorithm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        match self {
            Self::Aes128 => Box::new(PacketKey::<Aes128Gcm>::new(&key, iv, 1 << 23, 1 << 52)),
            Self::Aes256 => Box::new(PacketKey::<Aes256Gcm>::new(&key, iv, 1 << 23, 1 << 52)),
            Self::Chacha20 => Box::new(PacketKey::<ChaCha20Poly1305>::new(
                &key,
                iv,
                u64::MAX,
                1 << 36,
            )),
        }
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        match self {
            Self::Aes128 => Box::new(HeaderKey(aes::Aes128::new_from_slice(key.as_ref()).ok())),
            Self::Aes256 => Box::new(HeaderKey(aes::Aes256::new_from_slice(key.as_ref()).ok())),
            Self::Chacha20 => {
                let bytes = <&[u8; 32]>::try_from(key.as_ref()).ok();
                Box::new(HeaderKey(
                    bytes.map(|key| ChachaHeader(Zeroizing::new(*key))),
                ))
            }
        }
    }

    fn aead_key_len(&self) -> usize {
        self.key_size()
    }
}

struct PacketKey<K> {
    key: Option<K>,
    iv: Iv,
    confidentiality: u64,
    integrity: u64,
}

impl<K: TlsCipher> PacketKey<K> {
    fn new(key: &AeadKey, iv: Iv, confidentiality: u64, integrity: u64) -> Self {
        Self {
            key: K::new_from_slice(key.as_ref()).ok(),
            iv,
            confidentiality,
            integrity,
        }
    }
}

impl<K: TlsCipher> quic::PacketKey for PacketKey<K> {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        self.encrypt_in_place_for_path(0, packet_number, header, payload)
    }

    fn encrypt_in_place_for_path(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let key = self.key.as_ref().ok_or(Error::EncryptError)?;
        if packet_number > MAX_QUIC_PACKET_NUMBER {
            return Err(Error::EncryptError);
        }
        let nonce = Nonce::for_path(path_id, &self.iv, packet_number).0;
        let tag = seal(key, &nonce, header, payload)?;
        Ok(quic::Tag::from(tag.as_slice()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.decrypt_in_place_for_path(0, packet_number, header, payload)
    }

    fn decrypt_in_place_for_path<'a>(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let key = self.key.as_ref().ok_or(Error::DecryptError)?;
        if packet_number > MAX_QUIC_PACKET_NUMBER {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::for_path(path_id, &self.iv, packet_number).0;
        open(key, &nonce, header, payload)
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity
    }
}

trait HeaderMask: Send + Sync {
    fn mask(&self, sample: &[u8; 16]) -> [u8; 5];
}

impl<K: BlockCipherEncrypt<BlockSize = U16> + Send + Sync> HeaderMask for K {
    fn mask(&self, sample: &[u8; 16]) -> [u8; 5] {
        let mut block = (*sample).into();
        self.encrypt_block(&mut block);
        [block[0], block[1], block[2], block[3], block[4]]
    }
}

struct ChachaHeader(Zeroizing<[u8; 32]>);

impl HeaderMask for ChachaHeader {
    fn mask(&self, sample: &[u8; 16]) -> [u8; 5] {
        let (counter, nonce) = sample.split_at(4);
        let counter = u32::from_le_bytes([counter[0], counter[1], counter[2], counter[3]]);
        let mut iv = chacha20::Nonce::default();
        iv.copy_from_slice(nonce);
        let mut core = ChaChaCore::<R20, Ietf>::new((&*self.0).into(), &iv);
        // RFC 9001 allows every sampled counter, including u32::MAX. Generate
        // exactly one block with no subsequent use of the incremented counter.
        core.set_block_pos(counter);
        let mut block = Zeroizing::new([0; 64]);
        core.write_keystream_block((&mut *block).into());
        [block[0], block[1], block[2], block[3], block[4]]
    }
}

struct HeaderKey<K>(Option<K>);

impl<K: HeaderMask> HeaderKey<K> {
    fn apply(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        decrypt: bool,
    ) -> Result<(), Error> {
        let key = self
            .0
            .as_ref()
            .ok_or_else(|| Error::General("invalid QUIC header protection key".into()))?;
        let sample = <&[u8; 16]>::try_from(sample)
            .map_err(|_| Error::General("invalid QUIC header protection sample length".into()))?;
        if packet_number.len() > 4 {
            return Err(Error::General("invalid QUIC packet number length".into()));
        }
        let [mask, pn_mask @ ..] = key.mask(sample);
        let mask = mask & if *first & 0x80 == 0 { 0x1f } else { 0x0f };
        let unprotected = if decrypt { *first ^ mask } else { *first };
        let pn_len = usize::from(unprotected & 3) + 1;
        let packet_number = packet_number
            .get_mut(..pn_len)
            .ok_or_else(|| Error::General("truncated QUIC packet number".into()))?;
        *first ^= mask;
        for (byte, mask) in packet_number.iter_mut().zip(pn_mask) {
            *byte ^= mask;
        }
        Ok(())
    }
}

impl<K: HeaderMask> quic::HeaderProtectionKey for HeaderKey<K> {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.apply(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.apply(sample, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::quic::Algorithm as _;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixed QUIC known-answer assertions"
    )]
    fn chacha_short_header_packet_matches_rfc_9001() -> Result<(), Error> {
        // RFC 9001 Appendix A.5.
        let packet_number = 654_360_564;
        let packet_key = AeadKey::from([
            0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1, 0xb2, 0x18, 0x20, 0x94, 0xf6, 0x9c,
            0xaa, 0x2e, 0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88, 0x96, 0x0a, 0x7a, 0x98, 0x49, 0x79,
            0xfb, 0x23, 0xe1, 0xc8,
        ]);
        let iv = Iv::from([
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44,
        ]);
        let header_key = AeadKey::from([
            0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc,
            0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b,
            0x0a, 0xb7, 0xa7, 0xa4,
        ]);
        let packet = CHACHA20_POLY1305.packet_key(packet_key, iv);
        let protection = CHACHA20_POLY1305.header_protection_key(header_key);
        let header = [0x42, 0x00, 0xbf, 0xf4];
        let mut body = [0; 17];
        body[0] = 1;
        let tag = packet.encrypt_in_place(packet_number, &header, &mut body[..1])?;
        body[1..].copy_from_slice(tag.as_ref());
        assert_eq!(
            body,
            [
                0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2,
                0x5a, 0x5b, 0xfb
            ]
        );

        let mut first = header[0];
        let mut number = [header[1], header[2], header[3]];
        protection.encrypt_in_place(&body[1..], &mut first, &mut number)?;
        assert_eq!((first, number), (0x4c, [0xfe, 0x41, 0x89]));
        protection.decrypt_in_place(&body[1..], &mut first, &mut number)?;
        assert_eq!((first, number), (0x42, [0x00, 0xbf, 0xf4]));
        assert_eq!(
            packet.decrypt_in_place(packet_number, &header, &mut body)?,
            [1]
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "exercise the exact record format and authentication failure"
    )]
    fn tls12_gcm_sends_explicit_nonce_and_authenticates_sequence() -> Result<(), Error> {
        let sequence = 0x0102_0304_0506_0708;
        let cipher = <Algorithm as Tls12AeadAlgorithm>::encrypter(
            &AES256_GCM,
            AeadKey::from([0; 32]),
            &[0x20; 4],
            &[0x10; 8],
        );
        let message = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: b"dns".as_slice().into(),
        };
        let mut cipher = cipher;
        let mut encrypted = cipher.encrypt(message, sequence)?;
        assert_eq!(
            &encrypted.payload.as_ref()[..8],
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
        );
        let mut dec = <Algorithm as Tls12AeadAlgorithm>::decrypter(
            &AES256_GCM,
            AeadKey::from([0; 32]),
            &[0x20; 4],
        );
        let input =
            InboundOpaqueMessage::new(encrypted.typ, encrypted.version, encrypted.payload.as_mut());
        assert_eq!(
            dec.decrypt(input, sequence + 1).err(),
            Some(Error::DecryptError),
        );
        let input =
            InboundOpaqueMessage::new(encrypted.typ, encrypted.version, encrypted.payload.as_mut());
        assert_eq!(dec.decrypt(input, sequence)?.payload, b"dns");
        Ok(())
    }

    #[test]
    fn chacha_header_allows_the_last_block_counter() {
        let protection = CHACHA20_POLY1305.header_protection_key(AeadKey::from([0; 32]));
        let mut sample = [0; 16];
        sample[..4].fill(0xff);
        let mut first = 0x42;
        let mut number = [1, 2, 3];
        assert!(
            protection
                .encrypt_in_place(&sample, &mut first, &mut number)
                .is_ok()
        );
        assert!(
            protection
                .decrypt_in_place(&sample, &mut first, &mut number)
                .is_ok()
        );
        assert_eq!((first, number), (0x42, [1, 2, 3]));
    }
}
