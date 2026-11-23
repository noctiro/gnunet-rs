use super::{Decision, FixedEngine, Instance, Query, Work, wire};
use gnunet_types::Error;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert exact fixed-lane wire behavior"
)]
fn fixed_lanes_keep_same_dns_id_requests_independent_and_scrub_retired_bytes() -> Result<(), Error>
{
    const WIDTH: usize = 32;
    let mut arena = [0xa5; 2 * WIDTH + 1];
    let domain = Instance::new();
    let query = [0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut answer = [0; WIDTH];
    answer[..query.len()].copy_from_slice(&query);
    answer[2] |= 0x80;
    {
        let mut owner = FixedEngine::<1, 2>::with_storage(&domain, WIDTH, &mut arena)?;
        let source = owner.attach_source()?;
        let client = owner.attach_client()?;
        owner.init(client, wire::PRE_RESOLUTION)?;
        let first = owner.intercept(source, Query::decode(&query)?, 1, 100)?;
        let second = owner.intercept(source, Query::decode(&query)?, 1, 101)?;
        assert_eq!(
            owner.next_work(first)?,
            Work::Client {
                request: first,
                client
            }
        );
        assert_eq!(
            owner.intercept(source, Query::decode(&query)?, 1, 100),
            Err(Error::Capacity)
        );
        let mut callback = [0; WIDTH + 16];
        let (effect, n) = owner.prepare_client(first, client, &mut callback)?;
        let request = wire::Response::decode(&callback[..n])?;
        assert_eq!(request.dns, query);
        owner.queued(effect)?;
        owner.written(effect)?;
        assert!(owner.reply(client, request.id, Decision::Answer(&answer))?);
        assert_eq!(owner.payload(second)?, query);
        assert_eq!(
            owner.next_work(first)?,
            Work::Source {
                request: first,
                source
            }
        );
        let ready = owner.prepare_source(first)?;
        assert_eq!(ready.dns(), answer);
        let effect = ready.effect();
        owner.queued(effect)?;
        owner.written(effect)?;
        owner.retire(first)?;
        let third = owner.intercept(source, Query::decode(&query)?, 2, 102)?;
        assert_ne!(first, third);
        assert_eq!(owner.payload(first), Err(Error::StaleGeneration));
        assert_eq!(owner.payload_bytes(), 2 * query.len());
    }
    assert!(arena[..2 * WIDTH].iter().all(|&byte| byte == 0));
    assert_eq!(arena[2 * WIDTH], 0xa5);
    Ok(())
}
