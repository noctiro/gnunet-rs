//! Source-only actual frame roundtrips; no daemon or peer execution credit.
use super::*;
fn check(v: bool) -> Result<(), Error> {
    if v { Ok(()) } else { Err(Error::Conflict) }
}
#[test]
fn normal_join_insert_context_and_marker_preserve_exact_types_and_signed_fields()
-> Result<(), Error> {
    let peers = [[1; 32], [2; 32]];
    let mut bytes = [0; 256];
    let join = ClientRequest::Join(Join {
        session: [3; 64],
        start: 7,
        deadline: 19,
        peers: &peers,
    });
    let n = join.encode(&mut bytes)?;
    check(n == 152 && ClientRequest::decode(&bytes[..n])? == join)?;
    let insert = ClientRequest::Insert {
        element_type: 24,
        data: &[0, 9],
    };
    let n = insert.encode(&mut bytes)?;
    check(bytes[4..6] == [0, 24])?;
    check(ClientRequest::decode(&bytes[..n])? == insert)?;
    let context = RoundContext {
        kind: 0,
        peer1: 0,
        peer2: 1,
        repetition: -1,
        leader: -1,
        contested: 0,
    };
    let n = context.encode(&mut bytes)?;
    check(n == 16 && RoundContext::decode(&bytes[..n])? == context)?;
    let block = Block {
        payload_type: 0,
        marker: 2,
        data: &[0, 0, 0, 0, 0, 0, 0, 7, 1],
    };
    let n = block.encode(&mut bytes)?;
    check(n == 12 && Block::decode(&bytes[..n])?.size_marker()? == (7, 1))?;
    check(ClientResponse::decode(&[0, 4, 2, 13])? == ClientResponse::Done)?;
    check(ClientRequest::decode(&[0, 5, 2, 12, 0]).is_err())
}
