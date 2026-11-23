//! Public DNS phase/source ownership fixtures without socket, route or device I/O.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Phase transitions and original source/output capabilities are asserted"
)]
use crate::*;
use gnunet_types::Error;

const QUERY: [u8; 12] = [0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
fn engine(domain: &Instance) -> Result<Engine<'_>, Error> {
    Engine::new(
        domain,
        Limits {
            clients: 4,
            requests: 4,
            bytes: 4096,
            payload_bytes: 512,
        },
    )
}
fn answer() -> [u8; 12] {
    let mut response = QUERY;
    response[2] |= 0x80;
    response
}
fn callback<'id>(
    engine: &mut Engine<'id>,
    request: Request<'id>,
    client: Client<'id>,
) -> Result<[u8; 8], Error> {
    let mut frame = [0; 128];
    let (effect, n) = engine.prepare_client(request, client, &mut frame)?;
    let id = wire::Response::decode(&frame[..n])?.id;
    engine.queued(effect)?;
    engine.exposed(effect)?;
    engine.written(effect)?;
    Ok(id)
}
fn resolve<'id>(engine: &mut Engine<'id>, request: Request<'id>) -> Result<(), Error> {
    assert_eq!(engine.next_work(request)?, Work::Resolve(request));
    let job = engine.resolving(request)?;
    engine.resolved(job, &answer())
}

#[test]
fn native_post_uses_the_last_external_post_result_before_response_monitor() -> Result<(), Error> {
    let domain = Instance::new();
    let mut engine = engine(&domain)?;
    let source = engine.attach_source()?;
    let external = engine.attach_client()?;
    engine.init(external, wire::POST_RESOLUTION)?;
    let monitor = engine.attach_client()?;
    engine.init(monitor, wire::RESPONSE_MONITOR)?;
    let request = engine.intercept(source, Query::decode(&QUERY)?, 1, 100)?;
    resolve(&mut engine, request)?;
    let mut scratch = [0; 32];
    assert_eq!(
        engine.next_work_with_post(request, &mut scratch, |_, _| Err(Error::Conflict))?,
        Work::Client {
            request,
            client: external
        }
    );
    let id = callback(&mut engine, request, external)?;
    let mut external_answer = answer();
    external_answer[3] = 0x20;
    engine.reply(external, id, Decision::Answer(&external_answer))?;
    let translated = answer();
    assert_eq!(
        engine.next_work_with_post(request, &mut scratch, |payload, scratch| {
            assert_eq!(payload, external_answer);
            scratch[..translated.len()].copy_from_slice(&translated);
            Ok(Some(translated.len()))
        })?,
        Work::Client {
            request,
            client: monitor
        }
    );
    let mut frame = [0; 128];
    let (effect, n) = engine.prepare_client(request, monitor, &mut frame)?;
    let callback = wire::Response::decode(&frame[..n])?;
    assert_eq!(callback.dns, translated);
    engine.queued(effect)?;
    engine.written(effect)?;
    engine.reply(monitor, callback.id, Decision::Forward)?;
    assert_eq!(
        engine.next_work_with_post(request, &mut scratch, |_, _| Err(Error::Conflict))?,
        Work::Source { request, source }
    );
    assert_eq!(engine.prepare_source(request)?.dns(), translated);
    Ok(())
}

#[test]
fn actual_phase_results_original_sources_and_local_write_boundaries() -> Result<(), Error> {
    let domain = Instance::new();
    let mut engine = engine(&domain)?;
    let source = engine.attach_source()?;
    let monitor = engine.attach_client()?;
    engine.init(monitor, wire::REQUEST_MONITOR | wire::RESPONSE_MONITOR)?;
    let first = engine.attach_client()?;
    engine.init(first, wire::PRE_RESOLUTION)?;
    let newest = engine.attach_client()?;
    engine.init(newest, wire::PRE_RESOLUTION | wire::POST_RESOLUTION)?;
    let request = engine.intercept(source, Query::decode(&QUERY)?, 1, 1000)?;
    assert_eq!(
        engine.next_work(request)?,
        Work::Client {
            request,
            client: monitor
        }
    );
    let id = callback(&mut engine, request, monitor)?;
    engine.reply(monitor, id, Decision::Forward)?;
    assert_eq!(
        engine.next_work(request)?,
        Work::Client {
            request,
            client: newest
        }
    );
    let id = callback(&mut engine, request, newest)?;
    engine.reply(newest, id, Decision::Answer(&answer()))?;
    // A pre-resolution answer skips older providers and the resolver.
    assert_eq!(
        engine.next_work(request)?,
        Work::Client {
            request,
            client: newest
        }
    );
    let id = callback(&mut engine, request, newest)?;
    engine.reply(newest, id, Decision::Forward)?;
    assert_eq!(
        engine.next_work(request)?,
        Work::Client {
            request,
            client: monitor
        }
    );
    let id = callback(&mut engine, request, monitor)?;
    engine.reply(monitor, id, Decision::Forward)?;
    assert_eq!(engine.next_work(request)?, Work::Source { request, source });
    let original = engine.payload(request)?.as_ptr();
    let prepared = engine.prepare_source(request)?;
    assert_eq!(prepared.dns(), answer());
    assert!(
        core::ptr::eq(original, prepared.dns().as_ptr()),
        "source preparation borrows the retained DNS allocation"
    );
    let rejected = prepared.effect();
    assert_eq!(rejected.destination(), Destination::Source(source));
    engine.reject_prepared(rejected)?;
    let effect = engine.prepare_source(request)?.effect();
    assert_eq!(engine.queued(rejected), Err(Error::StaleGeneration));
    engine.queued(effect)?;
    assert_eq!(engine.retire(request), Err(Error::WouldBlock));
    engine.exposed(effect)?;
    engine.written(effect)?;
    assert_eq!(engine.next_work(request)?, Work::Retire(request));
    engine.retire(request)?;
    let pending = engine.intercept(source, Query::decode(&QUERY)?, 2, 1000)?;
    assert_eq!(
        engine.next_work(pending)?,
        Work::Client {
            request: pending,
            client: monitor
        }
    );
    let _callback_id = callback(&mut engine, pending, monitor)?;
    engine.source_lost(source)?;
    assert_eq!(
        engine.next_work(pending)?,
        Work::Close(Destination::Client(monitor))
    );
    assert_eq!(engine.retire(pending), Err(Error::WouldBlock));
    engine.client_lost(monitor)?;
    engine.retire(pending)?;
    let replacement = engine.attach_source()?;
    assert_ne!(source, replacement);
    assert_eq!(
        engine.intercept(source, Query::decode(&QUERY)?, 2, 1000),
        Err(Error::StaleGeneration)
    );
    Ok(())
}

#[test]
fn source_output_retirement_isolated_from_source_and_other_requests() -> Result<(), Error> {
    let domain = Instance::new();
    let mut engine = engine(&domain)?;
    let source = engine.attach_source()?;
    let first = engine.intercept(source, Query::decode(&QUERY)?, 1, 1000)?;
    let second = engine.intercept(source, Query::decode(&QUERY)?, 1, 2000)?;
    resolve(&mut engine, first)?;
    assert_eq!(
        engine.next_work(first)?,
        Work::Source {
            request: first,
            source
        }
    );
    let effect = engine.prepare_source(first)?.effect();
    assert_eq!(engine.source_stopped(effect), Err(Error::Conflict));
    engine.queued(effect)?;
    engine.exposed(effect)?;
    engine.abort(first)?;
    assert_eq!(engine.retire(first), Err(Error::WouldBlock));
    engine.source_stopped(effect)?;
    assert_eq!(engine.next_work(first)?, Work::Retire(first));
    engine.retire(first)?;
    assert_eq!(engine.next_work(second)?, Work::Resolve(second));
    let replacement = engine.intercept(source, Query::decode(&QUERY)?, 2, 3000)?;
    assert_eq!(engine.source_stopped(effect), Err(Error::StaleGeneration));
    assert_eq!(engine.next_work(replacement)?, Work::Resolve(replacement));
    resolve(&mut engine, second)?;
    assert_eq!(
        engine.next_work(second)?,
        Work::Source {
            request: second,
            source
        }
    );
    let effect = engine.prepare_source(second)?.effect();
    engine.queued(effect)?;
    engine.written(effect)?;
    engine.retire(second)?;
    engine.abort(replacement)?;
    engine.retire(replacement)?;
    assert_eq!(engine.payload_bytes(), 0);
    Ok(())
}

#[test]
fn foreign_source_output_and_wrong_phase_preserve_original_capabilities() -> Result<(), Error> {
    let domain = Instance::new();
    let mut first = engine(&domain)?;
    let mut second = engine(&domain)?;
    let source = first.attach_source()?;
    let foreign = second.attach_source()?;
    assert_eq!(
        first.intercept(foreign, Query::decode(&QUERY)?, 0, 100),
        Err(Error::StaleGeneration)
    );
    assert_eq!(first.payload_bytes(), 0);
    assert_eq!(first.requests().count(), 0);
    let request = first.intercept(source, Query::decode(&QUERY)?, 0, 100)?;
    assert!(matches!(
        first.prepare_source(request),
        Err(Error::NotReady)
    ));
    resolve(&mut first, request)?;
    assert_eq!(first.next_work(request)?, Work::Source { request, source });
    let effect = first.prepare_source(request)?.effect();
    assert_eq!(second.queued(effect), Err(Error::StaleGeneration));
    assert_eq!(second.source_stopped(effect), Err(Error::StaleGeneration));
    assert_eq!(first.written(effect), Err(Error::Conflict));
    first.queued(effect)?;
    assert_eq!(first.reject_prepared(effect), Err(Error::Conflict));
    first.written(effect)?;
    first.retire(request)?;
    let replaced = first.intercept(source, Query::decode(&QUERY)?, 1, 100)?;
    assert_ne!(request, replaced);
    assert_eq!(first.queued(effect), Err(Error::StaleGeneration));
    assert_eq!(first.next_work(replaced)?, Work::Resolve(replaced));
    first.abort(replaced)?;
    first.retire(replaced)?;
    assert_eq!(first.payload_bytes(), 0);
    Ok(())
}

mod limits;
