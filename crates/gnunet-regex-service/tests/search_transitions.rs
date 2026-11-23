//! Shared REGEX queries work with caller-owned buffers and the default features.

use gnunet_crypto::EddsaPrivateKey;
use gnunet_regex::{BlockEdge, accept::AcceptMaterial, encode_state, proof_key};
use gnunet_regex_service::{QueryKind, SearchQuery};
use gnunet_types::Error;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert the official lookup coordinates, xquery bytes and transition order"
)]
fn traverses_the_first_longest_edge_and_requests_an_accept_block() -> Result<(), Error> {
    let prefix = b"abcdefghijklmnopqrstuvwx";
    let input = b"abcdefghijklmnopqrstuvwxab";
    let terminal_proof = b"longest destination";
    let terminal_key = proof_key(terminal_proof);
    let start = SearchQuery::start(input)?;
    assert_eq!(start.key(), &proof_key(prefix));
    assert_eq!(start.offset(), prefix.len());
    assert_eq!(start.kind(), QueryKind::State);
    assert_eq!(SearchQuery::start(b"a\0b"), Err(Error::InvalidInput));

    let mut xquery = [0xFF; 4];
    assert_eq!(
        start.write_xquery(input, &mut xquery[..2]),
        Err(Error::Capacity)
    );
    assert_eq!(xquery, [0xFF; 4]);
    assert_eq!(start.write_xquery(input, &mut xquery)?, 3);
    assert_eq!(xquery, *b"ab\0\xFF");
    assert!(start.matches_reply(start.key(), 22));
    assert!(!start.matches_reply(start.key(), 23));
    assert!(!start.matches_reply(&terminal_key, 22));

    let edges = [
        BlockEdge {
            label: b"",
            destination: [1; 64],
        },
        BlockEdge {
            label: b"a",
            destination: [2; 64],
        },
        BlockEdge {
            label: b"ab",
            destination: terminal_key,
        },
        BlockEdge {
            label: b"ab",
            destination: [3; 64],
        },
    ];
    let mut block = [0; 320];
    let size = encode_state(prefix, true, &edges[..], &mut block)?;
    let step = start.state(input, &block[..size])?;
    assert_eq!(step.inspected, edges.len());
    let terminal = step.next.ok_or(Error::InvalidInput)?;
    assert_eq!(terminal.kind(), QueryKind::State);
    assert_eq!(terminal.key(), &terminal_key);
    assert_eq!(terminal.offset(), input.len());
    assert_eq!(
        terminal.state(input, &block[..size]),
        Err(Error::Authentication)
    );
    assert_eq!(terminal.write_xquery(input, &mut xquery)?, 1);
    assert_eq!(xquery[0], 0);

    let no_edges: &[BlockEdge<'_>] = &[];
    let size = encode_state(terminal_proof, false, no_edges, &mut block)?;
    assert_eq!(terminal.state(input, &block[..size])?.next, None);
    let size = encode_state(terminal_proof, true, no_edges, &mut block)?;
    let step = terminal.state(input, &block[..size])?;
    assert_eq!(step.inspected, 0);
    let accept = step.next.ok_or(Error::InvalidInput)?;
    assert_eq!(accept.kind(), QueryKind::Accept);
    assert!(accept.matches_reply(&terminal_key, 23));
    assert_eq!(accept.suffix(input)?, None);
    assert_eq!(accept.write_xquery(input, &mut [])?, 0);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert that only a current signature for the queried key authenticates a peer"
)]
fn accepting_query_requires_the_original_key_and_a_current_signature() -> Result<(), Error> {
    let input = b"peer";
    let state = SearchQuery::start(input)?;
    let mut block = [0; 8 + b"peer".len()];
    let no_edges: &[BlockEdge<'_>] = &[];
    let size = encode_state(input, true, no_edges, &mut block)?;
    let accept = state
        .state(input, &block[..size])?
        .next
        .ok_or(Error::InvalidInput)?;

    let signer = EddsaPrivateKey::from_seed([11; 32]);
    let expires = 40;
    let mut signed = AcceptMaterial::new(*accept.key(), expires).sign(&signer)?;
    assert!(matches!(
        state.accept(&signed, expires),
        Err(Error::InvalidInput)
    ));
    let peer = accept.accept(&signed, expires)?;
    assert_eq!(peer.peer(), *signer.public_key().as_bytes());
    assert_eq!(peer.checked_at(), expires);
    assert!(matches!(
        accept.accept(&signed, expires + 1),
        Err(Error::Timeout)
    ));

    let unrelated = AcceptMaterial::new(proof_key(b"other"), expires).sign(&signer)?;
    assert!(matches!(
        accept.accept(&unrelated, expires),
        Err(Error::Authentication)
    ));
    let last = signed.last_mut().ok_or(Error::Truncated)?;
    *last ^= 1;
    assert!(matches!(
        accept.accept(&signed, expires),
        Err(Error::Authentication)
    ));
    Ok(())
}
