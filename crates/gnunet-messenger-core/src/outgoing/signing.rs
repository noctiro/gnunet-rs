//! Canonical signing drafts backed only by the encoded body.

use crate::{Error, Hash, crypto::signature::SigningHeader, wire};
use gnunet_crypto::hash512_parts;
use gnunet_types::Error as Fault;
use wire::{body::Body, profile::Profile};

/// Encode the original body and hash the unsigned fields in wire order.
/// The caller supplies an exact body-sized, zeroizing buffer and checks full frame limits.
pub(super) fn encode(
    body: Body<'_>,
    profile: Profile,
    header: SigningHeader<'_>,
    output: &mut [u8],
) -> Result<Hash, Error> {
    if body.encode(profile, output)? != output.len() {
        return Err(Fault::InvalidInput.into());
    }
    Ok(hash512_parts(&[
        &header.timestamp.to_be_bytes(),
        header.sender_id,
        header.previous,
        &body.kind().value().to_be_bytes(),
        output,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signature::message_hash;
    use gnunet_types::AbsoluteTime;
    use wire::{
        KeyType, SensitiveBytes,
        body::Text,
        envelope::{HEADER_LEN, Header, SIGNATURE_LEN, Signature},
        message::{self, Message},
        padding,
    };

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions compare the draft with the original wire encoder"
    )]
    fn draft_matches_the_wire_digest_without_padding() -> Result<(), Error> {
        const TEXT: &[u8; 14] = b"original draft";
        let body = Body::Text {
            text: Text::new(TEXT)?,
        };
        let profile = Profile::BIG_255;
        let header = SigningHeader {
            timestamp: AbsoluteTime::from_micros(0x0123_4567_89ab_cdef),
            sender_id: &[0x11; 32],
            previous: &[0x22; 64],
        };
        let mut encoded_body = [0; TEXT.len()];
        let digest = encode(body, profile, header, &mut encoded_body)?;

        let mut tagged = [0x55; SIGNATURE_LEN];
        tagged[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
        let mut frame = [0; HEADER_LEN + TEXT.len() + 7];
        let frame_len = message::encode(
            Header {
                signature: Signature::new(&tagged)?,
                timestamp: header.timestamp,
                sender_id: header.sender_id,
                previous: header.previous,
                kind: body.kind(),
            },
            body,
            profile,
            padding::Encode::ToLength {
                total: frame.len(),
                noise: SensitiveBytes::new(&[0x33; 4]),
            },
            &mut frame,
        )?;
        let original = Message::decode(&frame[..frame_len], profile, padding::Decode::Required)?;
        assert_eq!(&encoded_body, TEXT);
        assert_eq!(digest, message_hash(original));
        assert_eq!(
            encode(body, profile, header, &mut [0; TEXT.len() + 1]),
            Err(Fault::InvalidInput.into())
        );
        Ok(())
    }
}
