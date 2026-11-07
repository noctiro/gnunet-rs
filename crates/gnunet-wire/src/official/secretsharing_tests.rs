//! Exact canonical shapes and actual nested carrier extents. No signature,
//! FAIR proof, native service or successful DKG is manufactured by these cases.
use super::*;
use crate::official::{cadet, consensus, set};
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}

#[test]
fn reveal_extent_is_shared_by_both_codecs_and_checked_before_output_mutation() -> Result<(), Error>
{
    let encryptions = [[0; FAIR_ENCRYPTION_BYTES]; 2];
    let coefficients = [[0; FIELD_BYTES]; 2];
    let fields = RevealFields {
        signature: &[0; 64],
        peer: &[9; 32],
        encryptions: &encryptions,
        coefficients: &coefficients,
    };
    let mut bytes = [0; 3696];
    check(reveal_encoded_len(2, 2)? == bytes.len() && fields.encoded_len()? == bytes.len())?;
    let n = fields.encode(&mut bytes)?;
    let element = SignedElement::reveal(&bytes[..n], 2, 2)?;
    check(element.peer()? == &[9; 32] && element.purpose() == DKG2_PURPOSE)?;
    check(element.encryption(1)?.is_some() && element.encryption(2)?.is_none())?;
    check(element.coefficient(1)?.is_some() && element.coefficient(2)?.is_none())?;
    check(SignedElement::reveal(&bytes[..n], 2, 1).is_err())?;
    let mut short = [0x55; 3695];
    check(fields.encode(&mut short) == Err(Error::Capacity))?;
    check(short.iter().all(|byte| *byte == 0x55))?;
    check(reveal_encoded_len(usize::MAX, 1) == Err(Error::Overflow))?;
    check(reveal_encoded_len(1, usize::MAX) == Err(Error::Overflow))?;
    // A shape-only codec does not certify the semantic validity of these counts.
    check(reveal_encoded_len(0, 0)? == REVEAL_PREFIX)
}

#[test]
fn full_roster_reveals_distinguish_local_ipc_from_actual_set_cadet_capacity() -> Result<(), Error> {
    let encryptions = [[0; FAIR_ENCRYPTION_BYTES]; 39];
    let coefficients = [[0; FIELD_BYTES]; 7];
    let mut bytes = [0; 65284];
    let mut wrapped = [0; 65287];
    for (peers, threshold, expected, transportable) in [
        (38, 6, 64256, true),
        (38, 7, 64384, false),
        (39, 1, 65284, false),
    ] {
        let fields = RevealFields {
            signature: &[0; 64],
            peer: &[9; 32],
            encryptions: &encryptions[..peers],
            coefficients: &coefficients[..threshold],
        };
        let n = fields.encode(&mut bytes)?;
        check(n == expected && reveal_encoded_len(peers, threshold)? == n)?;
        check(SignedElement::reveal(&bytes[..n], peers, threshold).is_ok())?;
        check(
            consensus::ClientRequest::Insert {
                element_type: 0,
                data: &bytes[..n],
            }
            .encoded_len()?
                == n + 6,
        )?;
        let used = consensus::Block {
            payload_type: 0,
            marker: 0,
            data: &bytes[..n],
        }
        .encode(&mut wrapped)?;
        for message in [
            set::PeerMessage::UnionElements {
                element: set::Element {
                    element_type: consensus::BLOCK_TYPE,
                    data: &wrapped[..used],
                },
            },
            set::PeerMessage::UnionFullElement {
                element: set::Element {
                    element_type: consensus::BLOCK_TYPE,
                    data: &wrapped[..used],
                },
            },
        ] {
            let size = message.encoded_len(set::Abi::native());
            check(match size {
                Ok(length) => {
                    transportable
                        && length == n + consensus::ELEMENT_PREFIX + set::UNION_ELEMENT_PREFIX
                        && length <= cadet::MAX_APPLICATION_MESSAGE_SIZE
                }
                Err(Error::TooLarge) => !transportable,
                _ => false,
            })?;
        }
        check((n <= consensus::MAX_APPLICATION_ELEMENT_BYTES) == transportable)?;
    }
    check(consensus::MAX_APPLICATION_ELEMENT_BYTES == 64337)
}

#[test]
fn projected_share_rows_preserve_columns_threshold_and_nonmember_sentinel() -> Result<(), Error> {
    let peers = [[3; 32], [8; 32]];
    let sigmas = [[4; FIELD_BYTES], [9; FIELD_BYTES]];
    let indices = [7, u16::MAX];
    for order in [IndexOrder::Little, IndexOrder::Big] {
        let fields = ShareFields {
            threshold: 3,
            my_peer: 2,
            public_key: &[5; FIELD_BYTES],
            secret: &[6; FIELD_BYTES],
            peers: &peers,
            sigmas: &sigmas,
            original_indices: &indices,
            order,
        };
        let mut standalone = [0; SHARE_PREFIX + 2 * SHARE_ROW_BYTES];
        fields.encode(&mut standalone)?;
        let mut expected = [0; 4 + SHARE_PREFIX + 2 * SHARE_ROW_BYTES];
        Response::SecretReady(Share::decode(&standalone)?).encode(&mut expected)?;
        let writer = ShareEncoder {
            threshold: 3,
            my_peer: 2,
            public_key: fields.public_key,
            secret: fields.secret,
            peers: 2,
            order,
        };
        let mut actual = [0; 4 + SHARE_PREFIX + 2 * SHARE_ROW_BYTES];
        let mut visited = 0;
        writer.encode_secret_ready(&mut actual, |i| {
            visited += 1;
            ShareRow {
                peer: peers[i],
                sigma: sigmas[i],
                original_index: indices[i],
            }
        })?;
        check(actual == expected && visited == 2)?;
        let Response::SecretReady(share) = Response::decode(Frame::decode(&actual)?)? else {
            return Err(Error::Conflict);
        };
        check(share.threshold() == 3 && share.len() == 2 && share.my_peer() == 2)?;
        check(
            share.original_index(0, order)? == Some(7)
                && share.original_index(1, order)? == Some(u16::MAX),
        )?;
    }
    Ok(())
}

#[test]
fn projected_share_empty_result_and_frame_refusal_are_preflighted() -> Result<(), Error> {
    let mut writer = ShareEncoder {
        threshold: 4,
        my_peer: 0,
        public_key: &[0; FIELD_BYTES],
        secret: &[0; FIELD_BYTES],
        peers: 0,
        order: IndexOrder::native(),
    };
    let mut bytes = [0; SHARE_PREFIX + 4];
    let mut visited = 0;
    writer.encode_secret_ready(&mut bytes, |_| {
        visited += 1;
        ShareRow {
            peer: [0; 32],
            sigma: [0; FIELD_BYTES],
            original_index: 0,
        }
    })?;
    let Response::SecretReady(share) = Response::decode(Frame::decode(&bytes)?)? else {
        return Err(Error::Conflict);
    };
    check(visited == 0 && share.is_empty() && share.threshold() == 4 && share.my_peer() == 0)?;
    for count in [1, 403, usize::MAX] {
        writer.peers = count;
        let mut short = [0x55; 8];
        check(
            writer
                .encode_secret_ready(&mut short, |_| {
                    visited += 1;
                    ShareRow {
                        peer: [0; 32],
                        sigma: [0; FIELD_BYTES],
                        original_index: 0,
                    }
                })
                .is_err(),
        )?;
        check(visited == 0 && short == [0x55; 8])?;
    }
    Ok(())
}

#[test]
fn fair_fields_writer_preserves_all_original_widths_and_preflights_short_output()
-> Result<(), Error> {
    let fields = FairEncryptionFields {
        ciphertext: &[1; 516],
        h: &[2; 128],
        t1: &[3; 128],
        t2: &[4; 512],
        z: &[5; 128],
        w: &[6; 256],
    };
    let mut bytes = [0; FAIR_ENCRYPTION_BYTES];
    check(fields.encode(&mut bytes)? == FAIR_ENCRYPTION_BYTES)?;
    let decoded = FairEncryption::decode(&bytes)?;
    check(
        decoded.ciphertext()? == fields.ciphertext
            && decoded.h()? == fields.h
            && decoded.t1()? == fields.t1
            && decoded.t2()? == fields.t2
            && decoded.z()? == fields.z
            && decoded.w()? == fields.w,
    )?;
    let mut short = [0x55; FAIR_ENCRYPTION_BYTES - 1];
    check(fields.encode(&mut short) == Err(Error::Capacity))?;
    check(short.iter().all(|b| *b == 0x55))
}
