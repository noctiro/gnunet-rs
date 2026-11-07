//! Fixed-source scalarproduct layouts. These cases are source only until run.
use gnunet_types::Error;
use gnunet_wire::official::scalarproduct::{
    ClientRequest, ClientResponse, Element, PeerMessage, ResponseStatus,
};

fn check(condition: bool) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}

#[test]
fn signed_element_and_original_client_total() -> Result<(), Error> {
    let key = [0x42; 64];
    let first = Element {
        key: &key,
        value: i64::MIN,
    }
    .encode();
    let second = Element {
        key: &key,
        value: 0,
    }
    .encode();
    check(first[64..] == [0x80, 0, 0, 0, 0, 0, 0, 0])?;
    check(Element::decode(&first)?.value == i64::MIN)?;
    let elements = [first, second];
    let peer = [0x91; 32];
    let request = ClientRequest::Alice {
        total: 5,
        reserved: 0,
        session: &key,
        peer: &peer,
        elements: &elements,
    };
    let mut encoded = [0xa5; 256];
    check(request.encode(&mut encoded)? == 256)?;
    check(encoded[..16] == [1, 0, 2, 0x80, 0, 0, 0, 5, 0, 0, 0, 2, 0, 0, 0, 0])?;
    check(encoded[80..112] == peer)?;
    check(ClientRequest::decode(&encoded)? == request)?;
    encoded[11] = 3;
    check(ClientRequest::decode(&encoded).is_err())?;
    let mut short = [0x55; 255];
    check(request.encode(&mut short) == Err(Error::Capacity))?;
    check(short == [0x55; 255])?;
    Ok(())
}

#[test]
fn ecc_alice_count_is_pairs_bob_count_is_two() -> Result<(), Error> {
    let points = [[1; 32], [2; 32], [3; 32], [4; 32]];
    let message = PeerMessage::EccAlice { points: &points };
    let mut encoded = [0; 136];
    check(message.encode(&mut encoded)? == 136)?;
    check(encoded[..8] == [0, 136, 2, 0x8b, 0, 0, 0, 2])?;
    check(PeerMessage::decode(&encoded)? == message)?;
    encoded[7] = 4;
    check(PeerMessage::decode(&encoded).is_err())?;
    let mut bob = [0; 72];
    PeerMessage::EccBob {
        product_g: &points[0],
        product_h: &points[1],
    }
    .encode(&mut bob)?;
    check(bob[..8] == [0, 72, 2, 0x8c, 0, 0, 0, 2])?;
    bob[7] = 1;
    check(PeerMessage::decode(&bob).is_err())?;
    Ok(())
}

#[test]
fn paillier_bob_base_values_are_not_contained_entries() -> Result<(), Error> {
    let ciphertexts = [[0x11; 516], [0x22; 516], [0x33; 516], [0x44; 516]];
    let message = PeerMessage::PaillierBob {
        values: &ciphertexts,
    };
    let mut encoded = [0; 2072];
    check(message.encode(&mut encoded)? == 2072)?;
    check(encoded[..8] == [8, 24, 2, 0x87, 0, 0, 0, 1])?;
    check(PeerMessage::decode(&encoded)? == message)?;
    let mut part = [0; 2072];
    let message = PeerMessage::PaillierBobPart {
        values: &ciphertexts,
    };
    message.encode(&mut part)?;
    check(part[..8] == [8, 24, 2, 0x88, 0, 0, 0, 2])?;
    check(PeerMessage::decode(&part)? == message)?;
    part[7] = 1;
    check(PeerMessage::decode(&part).is_err())?;
    Ok(())
}

#[test]
fn original_result_bytes_range_and_unknown_status_are_preserved() -> Result<(), Error> {
    let product = [0, 0x80, 0];
    let reply = ClientResponse {
        status: ResponseStatus(0x1234),
        range: -1,
        product: &product,
    };
    let mut encoded = [0; 19];
    check(reply.encode(&mut encoded)? == 19)?;
    check(encoded[..4] == [0, 19, 2, 0x89])?;
    check(encoded[12..16] == [0xff; 4])?;
    check(ClientResponse::decode(&encoded)? == reply)?;
    encoded[7] = 2;
    check(ClientResponse::decode(&encoded).is_err())?;
    let empty = ClientResponse {
        status: ResponseStatus::SUCCESS,
        range: 0,
        product: &[],
    };
    let mut zero = [0; 16];
    empty.encode(&mut zero)?;
    check(ClientResponse::decode(&zero)? == empty)?;
    Ok(())
}
