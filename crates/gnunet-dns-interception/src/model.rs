//! One public packet/phase ownership fixture; no actual socket/process/route,
//! key, entropy, store or cryptographic primitive is invoked by this source.
use crate::*;
use gnunet_types::Error;
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
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The single public owner model asserts phase, original source and output facts"
)]
fn actual_phase_results_original_sources_and_local_write_boundaries() -> Result<(), Error> {
    let domain = Instance::new();
    let mut engine = Engine::new(
        &domain,
        Limits {
            clients: 4,
            requests: 4,
            bytes: 4096,
            payload_bytes: 512,
        },
    )?;
    // Explicit synthetic model providers, never advertised as actual MQ/TUN proof.
    let source = engine.attach_source()?;
    let monitor = engine.attach_client()?;
    engine.init(monitor, wire::REQUEST_MONITOR | wire::RESPONSE_MONITOR)?;
    let first = engine.attach_client()?;
    engine.init(first, wire::PRE_RESOLUTION)?;
    let newest = engine.attach_client()?;
    engine.init(newest, wire::PRE_RESOLUTION | wire::POST_RESOLUTION)?;
    let query = [0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut udp = [0; 8];
    udp[..2].copy_from_slice(&5555u16.to_be_bytes());
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    let mut ip = [0; 128];
    let n = gnunet_vpn::packet::build_parts(
        Address::V4([192, 0, 2, 1]),
        Address::V4([192, 0, 2, 53]),
        17,
        &udp,
        &query,
        &mut ip,
    )?;
    let request = engine.intercept(source, &ip[..n], 1, 1000)?;
    assert_eq!(
        engine.next_work(request)?,
        Work::Client {
            request,
            client: monitor
        }
    );
    let id = callback(&mut engine, request, monitor)?;
    engine.reply(monitor, id, Decision::Forward)?;
    // DLL_insert ordering: latest actual connection is first at phase snapshot.
    assert_eq!(
        engine.next_work(request)?,
        Work::Client {
            request,
            client: newest
        }
    );
    let id = callback(&mut engine, request, newest)?;
    let mut answer = query;
    answer[2] |= 0x80;
    engine.reply(newest, id, Decision::Answer(&answer))?;
    // A real pre-resolution answer skips older providers and actual DNSSTUB job.
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
    assert_eq!(engine.next_work(request)?, Work::Helper { request, source });
    let mut out = [0; 128];
    let (effect, len) = engine.prepare_helper(request, &mut out)?;
    let raw = helper_packet(&out[..len])?;
    let packet = gnunet_vpn::packet::Packet::parse(raw)?;
    packet.validate_checksums()?;
    assert_eq!(packet.ports()?, (53, 5555));
    engine.queued(effect)?;
    assert_eq!(engine.retire(request), Err(Error::WouldBlock));
    engine.exposed(effect)?;
    engine.written(effect)?;
    assert_eq!(engine.next_work(request)?, Work::Retire(request));
    engine.retire(request)?;
    let pending = engine.intercept(source, &ip[..n], 2, 1000)?;
    assert_eq!(
        engine.next_work(pending)?,
        Work::Client {
            request: pending,
            client: monitor
        }
    );
    let _callback_id = callback(&mut engine, pending, monitor)?;
    let old = source;
    engine.source_lost(source)?;
    assert_eq!(
        engine.next_work(pending)?,
        Work::Close(Destination::Client(monitor))
    );
    assert_eq!(engine.retire(pending), Err(Error::WouldBlock));
    engine.client_lost(monitor)?;
    engine.retire(pending)?;
    let replacement = engine.attach_source()?;
    assert_ne!(old, replacement);
    assert_eq!(
        engine.intercept(old, &ip[..n], 2, 1000),
        Err(Error::StaleGeneration)
    );
    Ok(())
}
