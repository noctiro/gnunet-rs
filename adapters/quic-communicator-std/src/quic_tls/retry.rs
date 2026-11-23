use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};
use quinn::{ConnectionId, crypto::UnsupportedVersion};

const TAG_LEN: usize = 16;

#[derive(Clone, Copy)]
pub(super) enum Version {
    V1,
    Draft,
}

impl TryFrom<u32> for Version {
    type Error = UnsupportedVersion;

    fn try_from(version: u32) -> Result<Self, Self::Error> {
        match version {
            0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Self::V1),
            0xff00_001d..=0xff00_0020 => Ok(Self::Draft),
            _ => Err(UnsupportedVersion),
        }
    }
}

impl Version {
    pub(super) const fn tls_version(self) -> rustls::quic::Version {
        match self {
            Self::V1 => rustls::quic::Version::V1,
            Self::Draft => rustls::quic::Version::V1Draft,
        }
    }

    // RFC 9001 §5.8 and the draft versions also recognized by Quinn.
    fn cipher(self) -> (Aes128Gcm, [u8; 12]) {
        let (key, nonce) = match self {
            Self::V1 => (
                [
                    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3,
                    0x68, 0xc8, 0x4e,
                ],
                [
                    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
                ],
            ),
            Self::Draft => (
                [
                    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c,
                    0xb9, 0x6b, 0xe1,
                ],
                [
                    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
                ],
            ),
        };
        (Aes128Gcm::new((&key).into()), nonce)
    }

    #[expect(
        clippy::expect_used,
        reason = "Quinn bounds Retry packets to one datagram"
    )]
    pub(super) fn seal(self, destination: &ConnectionId, packet: &[u8]) -> [u8; TAG_LEN] {
        let (cipher, nonce) = self.cipher();
        cipher
            .encrypt_inout_detached(
                (&nonce).into(),
                &pseudo_packet(destination, packet, &[]),
                (&mut [][..]).into(),
            )
            .expect("QUIC Retry packet bounds")
            .into()
    }

    pub(super) fn verify(self, destination: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let Some(tag_start) = payload.len().checked_sub(TAG_LEN) else {
            return false;
        };
        let (body, tag) = payload.split_at(tag_start);
        let Ok(tag) = <&[u8; TAG_LEN]>::try_from(tag) else {
            return false;
        };
        let (cipher, nonce) = self.cipher();
        cipher
            .decrypt_inout_detached(
                (&nonce).into(),
                &pseudo_packet(destination, header, body),
                (&mut [][..]).into(),
                tag.into(),
            )
            .is_ok()
    }
}

fn pseudo_packet(destination: &ConnectionId, header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + destination.len() + header.len() + body.len());
    // Quinn's ConnectionId limits the length to 20 bytes.
    bytes.push(destination.len() as u8);
    bytes.extend_from_slice(destination);
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(body);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9001_retry_integrity_vector() {
        let destination = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
        let header = [
            0xff, 0, 0, 0, 1, 0, 8, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5,
        ];
        let body = b"token";
        let tag = [
            0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24,
            0x96, 0xba,
        ];
        assert_eq!(
            Version::V1.seal(&destination, &[header.as_slice(), body].concat()),
            tag
        );
        let mut payload = [body.as_slice(), &tag].concat();
        assert!(Version::V1.verify(&destination, &header, &payload));
        payload[0] ^= 1;
        assert!(!Version::V1.verify(&destination, &header, &payload));
    }
}
