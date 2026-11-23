//! Persistent searches and result delivery with bounded duplicate history.
#![cfg(feature = "alloc")]

use gnunet_crypto::EddsaPrivateKey;
use gnunet_regex::{BlockEdge, Hash, accept::AcceptMaterial, encode_state, first_key};
use gnunet_regex_service::{ClientId, Core, Error, JobId, Limits, Reply, Times, Work};
use gnunet_wire::official::regex::{Request, StringBytes};

const INPUT: &[u8] = b"match";

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Check query ownership, result delivery and expiry at each step"
)]
fn full_duplicate_cache_preserves_both_original_searches() -> Result<(), Error> {
    let mut core = Core::new(Limits {
        seen_results: 1,
        outputs: 1,
        ..Limits::default()
    })?;
    let first = core.attach()?;
    let second = core.attach()?;
    let now = Times {
        monotonic: 10,
        absolute: 20,
    };
    let string = StringBytes::new(INPUT)?;
    let (_, key) = first_key(INPUT);
    for client in [&first, &second] {
        core.handle(client, Request::Search { string }, now)?;
    }

    let mut state = [0; 8 + INPUT.len()];
    let no_edges: &[BlockEdge<'_>] = &[];
    encode_state(INPUT, true, no_edges, &mut state)?;
    let reply = Reply {
        expires: 40,
        key,
        kind: 22,
        block: &state,
        get_path: &[],
        put_path: &[],
    };
    let first_state = start_get(&mut core, &first, key, 22)?;
    let second_state = start_get(&mut core, &second, key, 22)?;
    core.receive(&first_state, reply, now)?;
    core.receive(&second_state, reply, now)?;

    let first_accept = start_get(&mut core, &first, key, 23)?;
    let second_accept = start_get(&mut core, &second, key, 23)?;
    let signer = EddsaPrivateKey::from_seed([53; 32]);
    let accepting = AcceptMaterial::new(key, now.absolute).sign(&signer)?;
    let get_path = [[11; 32]];
    let put_path = [[12; 32]];
    let accepted = Reply {
        kind: 23,
        block: &accepting,
        get_path: &get_path,
        put_path: &put_path,
        ..reply
    };
    for (client, other, get) in [
        (&first, &second, &first_accept),
        (&second, &first, &second_accept),
    ] {
        core.receive(get, accepted, now)?;
        let output = core.next_output(client)?.ok_or(Error::Order)?;
        let found = core.output(&output)?;
        assert_eq!(found.peer, *signer.public_key().as_bytes());
        assert_eq!(found.get_path, &get_path);
        assert_eq!(found.put_path, &put_path);
        assert!(core.next_output(other)?.is_none());
        core.queued(&output)?;
        core.written(&output)?;

        core.receive(get, accepted, now)?;
        assert!(core.next_output(client)?.is_none());
    }

    let later = Times {
        monotonic: 11,
        absolute: 21,
    };
    assert_eq!(
        core.receive(&second_accept, accepted, later),
        Err(Error::Protocol(gnunet_types::Error::Timeout))
    );
    assert_eq!(core.pending_jobs(), 4);
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Check that each backend GET belongs to the original search"
)]
fn start_get(
    core: &mut Core,
    owner: &ClientId,
    expected_key: Hash,
    expected_kind: u32,
) -> Result<JobId, Error> {
    let Some(Work::Get {
        job,
        client,
        key,
        kind,
        xquery,
        ..
    }) = core.next_work()?
    else {
        return Err(Error::Order);
    };
    assert_eq!(&client, owner);
    assert_eq!(key, expected_key);
    assert_eq!(kind, expected_kind);
    assert_eq!(xquery, if kind == 22 { &[0][..] } else { &[] });
    core.get_started(&job)?;
    Ok(job)
}
