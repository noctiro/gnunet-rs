//! Official IPC payload ceiling and actual retained-capacity refusal/reuse.
use super::*;
use alloc::vec;

#[test]
fn maximum_dns_body_fits_both_official_ipc_directions_without_transport_assumptions()
-> Result<(), Error> {
    let mut maximum = vec![0; MAX_DNS_BYTES];
    maximum[..QUERY.len()].copy_from_slice(&QUERY);
    let checked = Query::decode(&maximum)?;
    assert!(core::ptr::eq(checked.bytes().as_ptr(), maximum.as_ptr()));
    let domain = Instance::new();
    let mut engine = Engine::new(
        &domain,
        Limits {
            clients: 1,
            requests: 2,
            bytes: MAX_DNS_BYTES,
            payload_bytes: MAX_DNS_BYTES,
        },
    )?;
    let source = engine.attach_source()?;
    let monitor = engine.attach_client()?;
    engine.init(monitor, wire::REQUEST_MONITOR)?;
    let request = engine.intercept(source, checked, 1, 100)?;
    assert_eq!(
        engine.next_work(request)?,
        Work::Client {
            request,
            client: monitor
        }
    );
    let mut output = vec![0; 65_535];
    let (effect, count) = engine.prepare_client(request, monitor, &mut output)?;
    assert_eq!(count, 65_535);
    let response = wire::Response::decode(&output)?;
    assert_eq!(response.dns, maximum);
    assert_eq!(
        wire::Request::Reply {
            id: response.id,
            decision: Decision::Answer(response.dns)
        }
        .encoded_len()?,
        65_535
    );
    assert_eq!(
        engine.intercept(source, Query::decode(&QUERY)?, 1, 100),
        Err(Error::Capacity)
    );
    assert_eq!(engine.requests().count(), 1);
    assert!(engine.payload_bytes() <= MAX_DNS_BYTES);
    engine.reject_prepared(effect)?;
    engine.abort(request)?;
    engine.retire(request)?;
    assert_eq!(engine.payload_bytes(), 0);
    let replacement = engine.intercept(source, Query::decode(&QUERY)?, 1, 100)?;
    assert_eq!(
        engine.next_work(replacement)?,
        Work::Client {
            request: replacement,
            client: monitor
        }
    );
    maximum.push(0);
    assert!(matches!(Query::decode(&maximum), Err(Error::TooLarge)));
    assert!(matches!(Query::decode(&QUERY[..11]), Err(Error::Truncated)));
    assert!(matches!(Query::decode(&answer()), Err(Error::Malformed)));
    Ok(())
}

#[test]
fn owner_payload_limit_refuses_before_allocating_a_request() -> Result<(), Error> {
    let domain = Instance::new();
    let mut engine = engine(&domain)?;
    let source = engine.attach_source()?;
    let mut bytes = vec![0; 513];
    bytes[..QUERY.len()].copy_from_slice(&QUERY);
    assert_eq!(
        engine.intercept(source, Query::decode(&bytes)?, 1, 100),
        Err(Error::TooLarge)
    );
    assert_eq!(engine.requests().count(), 0);
    assert_eq!(engine.payload_bytes(), 0);
    assert_eq!(
        engine.intercept(source, Query::decode(&QUERY)?, 100, 100),
        Err(Error::Deadline)
    );
    assert_eq!(engine.requests().count(), 0);
    Ok(())
}
