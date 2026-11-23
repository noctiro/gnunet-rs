use bytes::BytesMut;
use quinn::crypto::{CryptoError, HeaderKey, KeyPair, Keys, PacketKey};
use rustls::quic::{self, HeaderProtectionKey};

pub(super) fn adapt(keys: quic::Keys) -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(Header(keys.local.header)),
            remote: Box::new(Header(keys.remote.header)),
        },
        packet: KeyPair {
            local: Box::new(Packet(keys.local.packet)),
            remote: Box::new(Packet(keys.remote.packet)),
        },
    }
}

pub(super) struct Packet(pub(super) Box<dyn quic::PacketKey>);

impl PacketKey for Packet {
    #[expect(
        clippy::expect_used,
        reason = "Quinn provides a bounded outgoing packet and tag storage"
    )]
    fn encrypt(&self, packet: u64, buffer: &mut [u8], header_len: usize) {
        let (header, body) = buffer.split_at_mut(header_len);
        let (payload, tag) = body.split_at_mut(body.len() - self.tag_len());
        let computed = self
            .0
            .encrypt_in_place(packet, header, payload)
            .expect("QUIC send packet bounds");
        tag.copy_from_slice(computed.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plaintext_len = self
            .0
            .decrypt_in_place(packet, header, payload.as_mut())
            .map_err(|_| CryptoError)?
            .len();
        payload.truncate(plaintext_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.0.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

struct Header(Box<dyn HeaderProtectionKey>);

impl Header {
    fn fields<'a>(&self, offset: usize, packet: &'a mut [u8]) -> Option<HeaderFields<'a>> {
        // The sample begins four bytes after the start of the packet number,
        // independent of the header's actual packet-number length.
        let (header, sample) = packet.split_at_mut_checked(offset.checked_add(4)?)?;
        let (first, rest) = header.split_first_mut()?;
        Some(HeaderFields {
            first,
            number: rest.get_mut(offset.checked_sub(1)?..)?,
            sample: sample.get(..self.sample_size())?,
        })
    }
}

struct HeaderFields<'a> {
    first: &'a mut u8,
    number: &'a mut [u8],
    sample: &'a [u8],
}

impl HeaderKey for Header {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        if let Some(fields) = self.fields(pn_offset, packet) {
            // Rustls leaves the packet unchanged on error. Quinn verifies the payload tag.
            let _status = self
                .0
                .decrypt_in_place(fields.sample, fields.first, fields.number);
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "Quinn sizes the outgoing packet for the header sample"
    )]
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let fields = self
            .fields(pn_offset, packet)
            .expect("QUIC send header bounds");
        self.0
            .encrypt_in_place(fields.sample, fields.first, fields.number)
            .expect("QUIC send header protection");
    }

    fn sample_size(&self) -> usize {
        self.0.sample_len()
    }
}
