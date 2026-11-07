//! Actual borrowed-storage/effect ownership, separate from copied-observation tests.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Storage/effect authority tests assert exact original bytes and unchanged staged failures."
)]
mod support;
use gnunet_client::resolver::{Family, Request, WireId};
use gnunet_dns::{AbsoluteTime, Error, Idna, Name, Packet, RData, Record, Type};
use gnunet_dnsstub::DnsStub;
use gnunet_resolver_service_core::{
    owner::{self as real, Effect, Evaluation, Payload, Resolver},
    storage::{Limits, TextScratch},
};
use gnunet_types::MonoInstant;
use support::{Memory, Store};
struct AsciiFixture;
impl Idna for AsciiFixture {
    fn to_ascii(&self, b: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if !b.is_ascii() {
            return Err(Error::Unavailable);
        }
        if b.len() > out.len() {
            return Err(Error::Capacity);
        }
        out[..b.len()].copy_from_slice(b);
        Ok(b.len())
    }
    fn to_unicode_label(&self, b: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.to_ascii(b, out)
    }
}
fn record(data: &'static [u8], expiry: u64) -> Result<Record<'static>, Error> {
    Ok(Record {
        name: Name::from_wire(b"\x01q\0")?,
        kind: Type(1),
        class: 7,
        expiration: AbsoluteTime::from_micros(expiry),
        data: RData::Raw(data),
    })
}
fn start<'a, I: Idna, R: FnMut(u32) -> Result<u32, Error>>(
    c: &mut Resolver<'a>,
    s: &mut real::Scratch<'a>,
    stub: &mut DnsStub<8, 271, 1>,
    client: real::ClientId,
    req: Request<'_>,
    p: &mut Evaluation<'_, I, R>,
    slot: u32,
) -> Result<(real::LookupId, gnunet_dnsstub::RequestId, [u8; 2]), Error> {
    let id = c.request(s, client, req, p)?.ok_or(Error::NotReady)?;
    let t = c.take_effect()?.ok_or(Error::NotReady)?;
    let bytes = match c.effect(t)? {
        Effect::StartQuery(q) => {
            assert_eq!(q.lookup, id);
            q.bytes.to_vec()
        }
        _ => return Err(Error::Malformed),
    };
    let a = stub.resolve(&bytes, p.mono, |_| Ok(slot))?;
    let token = a.request;
    c.query_admitted(s, id, a)?;
    c.release_effect(t)?;
    Ok((id, token, [bytes[0], bytes[1]]))
}
fn cancel_head(c: &mut Resolver<'_>, stub: &mut DnsStub<8, 271, 1>) -> Result<(), Error> {
    let t = c.take_effect()?.ok_or(Error::NotReady)?;
    let token = match c.effect(t)? {
        Effect::CancelQuery(token) => token,
        _ => return Err(Error::Malformed),
    };
    stub.resolve_cancel(token)?;
    c.release_effect(t)
}
#[test]
fn queued_output_survives_cache_expiry_and_old_tickets_cannot_release_replacement_payload()
-> Result<(), Error> {
    let mut memory = Memory::<1024, 65535>::new([1, 4, 0, 4, 8, 8], 8, 70000)?;
    let (mut c, mut s, _before) = memory.raw_views(1)?;
    let client = c.connect()?;
    let mut stub = DnsStub::<8, 271, 1>::new()?;
    stub.add_dns_ip("127.0.0.1")?;
    let mut native = vec![0; 1024];
    let mut work = vec![0; 1024];
    let mut wire = [0; 255];
    let mut random = |_| Ok(1);
    let mut p = Evaluation {
        mono: MonoInstant(0),
        utc: AbsoluteTime::from_micros(0),
        idna: &AsciiFixture,
        random: &mut random,
        text: TextScratch {
            native: &mut native,
            work: &mut work,
            wire_name: &mut wire,
        },
    };
    let req = Request::forward(WireId([1; 4]), Family::V4, b"q")?;
    let (id, token, dns) = start(&mut c, &mut s, &mut stub, client, req, &mut p, 0)?;
    let answer = [record(&[7, 8, 9, 10], 0)?];
    c.dns_result(
        &mut s,
        id,
        token,
        Packet::new(dns, 0, &[], &answer, &[], &[]),
        &mut p,
    )?;
    cancel_head(&mut c, &mut stub)?;
    // The old Output is still queued in core while expiry frees cache's own pins.
    p.mono = MonoInstant(1);
    p.utc = AbsoluteTime::from_micros(1);
    let next = c
        .request(&mut s, client, req, &mut p)?
        .ok_or(Error::NotReady)?;
    assert_eq!(c.cache().record_count(), 0);
    assert!(c.cache().live_bytes() >= 4);
    let old_ticket = c.take_effect()?.ok_or(Error::NotReady)?;
    assert!(
        matches!(c.effect(old_ticket)?,Effect::Output(o)if o.payload==Payload::Raw(&[7,8,9,10]))
    );
    assert_eq!(c.current_effect(), Some(old_ticket));
    assert_eq!(c.take_effect()?, Some(old_ticket));
    let copied = match c.effect(old_ticket)? {
        Effect::Output(o) => {
            let mut frame = vec![0; 32];
            let n = o.encode(&mut frame)?;
            frame.truncate(n);
            frame
        }
        _ => return Err(Error::Malformed),
    };
    assert_eq!(&copied[8..], &[7, 8, 9, 10]);
    c.release_effect(old_ticket)?;
    let end = c.take_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(c.effect(end)?,Effect::Output(o)if o.payload==Payload::End));
    c.release_effect(end)?;
    let qt = c.take_effect()?.ok_or(Error::NotReady)?;
    let qbytes = match c.effect(qt)? {
        Effect::StartQuery(q) => {
            assert_eq!(q.lookup, next);
            q.bytes.to_vec()
        }
        _ => return Err(Error::Malformed),
    };
    assert_eq!(c.release_effect(qt), Err(Error::NotReady));
    let a = stub.resolve(&qbytes, p.mono, |_| Ok(0))?;
    let nt = a.request;
    c.query_admitted(&mut s, next, a)?;
    c.release_effect(qt)?;
    let answer = [record(&[9; 4], u64::MAX)?];
    c.dns_result(
        &mut s,
        next,
        nt,
        Packet::new([qbytes[0], qbytes[1]], 0, &[], &answer, &[], &[]),
        &mut p,
    )?;
    cancel_head(&mut c, &mut stub)?;
    let newer = c.take_effect()?.ok_or(Error::NotReady)?;
    assert_eq!(c.release_effect(old_ticket), Err(Error::StaleGeneration));
    assert_eq!(c.current_effect(), Some(newer));
    assert!(matches!(c.effect(newer)?,Effect::Output(o)if o.payload==Payload::Raw(&[9;4])));
    // EOF revokes the in-flight view ticket and purges its unadmitted END.
    c.disconnect(&mut s, client)?;
    assert_eq!(c.release_effect(newer), Err(Error::StaleGeneration));
    assert_eq!(c.current_effect(), None);
    assert_eq!(c.effect_count(), 0);
    let replacement = c.connect()?;
    assert_ne!(replacement, client);
    assert_eq!(c.request(&mut s, replacement, req, &mut p)?, None);
    let last = c.take_effect()?.ok_or(Error::NotReady)?;
    assert_eq!(c.release_effect(newer), Err(Error::StaleGeneration));
    assert!(
        matches!(c.effect(last)?,Effect::Output(o)if o.client==replacement&&o.payload==Payload::Raw(&[9;4]))
    );
    c.release_effect(last)?;
    Ok(())
}
#[test]
fn wrong_pair_staging_is_rejected_before_either_owner_or_scratch_is_copied() -> Result<(), Error> {
    let mut one = Memory::<1024, 65535>::new([1, 2, 0, 2, 4, 4], 8, 70000)?;
    let mut two = Memory::<1024, 65535>::new([1, 2, 0, 2, 4, 4], 8, 70000)?;
    let (mut c, mut s, mut before) = one.raw_views(1)?;
    let (other, mut foreign, mut other_before) = two.raw_views(1)?;
    let client = c.connect()?;
    c.copy_logical_state_to(&mut before)?;
    other.copy_logical_state_to(&mut other_before)?;
    let mut native = [0; 1024];
    let mut work = [0; 1024];
    let mut wire = [0; 255];
    let mut rng = |_| Ok(1);
    let mut p = Evaluation {
        mono: MonoInstant(0),
        utc: AbsoluteTime::from_micros(0),
        idna: &AsciiFixture,
        random: &mut rng,
        text: TextScratch {
            native: &mut native,
            work: &mut work,
            wire_name: &mut wire,
        },
    };
    assert_eq!(
        c.request(
            &mut foreign,
            client,
            Request::forward(WireId([1; 4]), Family::V4, b"q")?,
            &mut p
        ),
        Err(Error::InvalidInput)
    );
    assert!(c == before);
    assert!(other == other_before);
    assert_eq!(
        other.copy_logical_state_to(&mut s),
        Err(Error::InvalidInput)
    );
    assert!(c == before);
    Ok(())
}
#[test]
fn resetting_same_buffers_requires_new_epoch_and_old_ticket_cannot_release_new_effect()
-> Result<(), Error> {
    let mut memory = Memory::<1024, 65535>::new([1, 2, 2, 2, 4, 4], 8, 70000)?;
    let old;
    {
        let (mut c, mut s, _b) = memory.raw_views(1)?;
        let client = c.connect()?;
        c.load_machine_files(&mut s, b"127.0.0.1 q\n", b"")?;
        let mut native = [0; 1024];
        let mut work = [0; 1024];
        let mut wire = [0; 255];
        let mut rng = |_| Err(Error::Entropy);
        let mut p = Evaluation {
            mono: MonoInstant(0),
            utc: AbsoluteTime::from_micros(0),
            idna: &AsciiFixture,
            random: &mut rng,
            text: TextScratch {
                native: &mut native,
                work: &mut work,
                wire_name: &mut wire,
            },
        };
        c.request(
            &mut s,
            client,
            Request::forward(WireId([1; 4]), Family::V4, b"q")?,
            &mut p,
        )?;
        old = c.take_effect()?.ok_or(Error::NotReady)?;
    }
    let (mut c, mut s, _b) = memory.raw_views(2)?;
    let client = c.connect()?;
    c.load_machine_files(&mut s, b"127.0.0.2 q\n", b"")?;
    let mut native = [0; 1024];
    let mut work = [0; 1024];
    let mut wire = [0; 255];
    let mut rng = |_| Err(Error::Entropy);
    let mut p = Evaluation {
        mono: MonoInstant(0),
        utc: AbsoluteTime::from_micros(0),
        idna: &AsciiFixture,
        random: &mut rng,
        text: TextScratch {
            native: &mut native,
            work: &mut work,
            wire_name: &mut wire,
        },
    };
    c.request(
        &mut s,
        client,
        Request::forward(WireId([2; 4]), Family::V4, b"q")?,
        &mut p,
    )?;
    let new = c.take_effect()?.ok_or(Error::NotReady)?;
    assert_ne!(new, old);
    assert_eq!(c.release_effect(old), Err(Error::StaleGeneration));
    assert!(matches!(c.effect(new)?,Effect::Output(o)if o.payload==Payload::Raw(&[127,0,0,2])));
    c.release_effect(new)?;
    Ok(())
}
#[test]
fn complete_65500_byte_record_is_copied_into_modest_aggregate_pool_without_per_record_width_product()
-> Result<(), Error> {
    let mut memory = Memory::<1024, 65535>::new([1, 2, 0, 2, 4096, 4], 8, 70000)?;
    let (mut c, mut s, _b) = memory.raw_views(1)?;
    let client = c.connect()?;
    let mut stub = DnsStub::<8, 271, 1>::new()?;
    stub.add_dns_ip("127.0.0.1")?;
    let mut native = vec![0; 1024];
    let mut work = vec![0; 1024];
    let mut wire = [0; 255];
    let mut rng = |_| Ok(1);
    let mut p = Evaluation {
        mono: MonoInstant(0),
        utc: AbsoluteTime::from_micros(0),
        idna: &AsciiFixture,
        random: &mut rng,
        text: TextScratch {
            native: &mut native,
            work: &mut work,
            wire_name: &mut wire,
        },
    };
    let (id, token, dns) = start(
        &mut c,
        &mut s,
        &mut stub,
        client,
        Request::forward(WireId([1; 4]), Family::V4, b"q")?,
        &mut p,
        0,
    )?;
    let mut bytes = vec![0xa5; 65500];
    let mut wire_packet = vec![0; 65535];
    let rr = Record {
        name: Name::from_wire(b"\x01q\0")?,
        kind: Type(65000),
        class: 3,
        expiration: AbsoluteTime::from_micros(60_000_000),
        data: RData::Raw(&bytes),
    };
    let records = [rr];
    let n = Packet::new(dns, 0x8180, &[], &records, &[], &[]).encode(p.utc, &mut wire_packet)?;
    assert!(n <= 65535);
    wire_packet.truncate(n);
    let mut arena_bytes = vec![0; 70000];
    {
        let mut arena = gnunet_dns::Arena::new(&mut arena_bytes);
        let mut queries = [];
        let mut records = [Record::EMPTY; 1];
        let parsed = Packet::parse(
            &wire_packet,
            p.utc,
            &mut arena,
            &mut queries,
            &mut records,
            gnunet_dns::Limits::DNS,
        )?;
        wire_packet.fill(0);
        c.dns_result(&mut s, id, token, parsed, &mut p)?;
    }
    bytes.fill(0);
    arena_bytes.fill(0);
    assert_eq!(c.cache().record_count(), 1);
    assert!(c.cache().live_bytes() >= 65500);
    assert!(c.cache().live_bytes() < 70000);
    assert_eq!(c.byte_capacity(), 70000);
    cancel_head(&mut c, &mut stub)?;
    let end = c.take_effect()?.ok_or(Error::NotReady)?;
    assert!(matches!(c.effect(end)?,Effect::Output(o)if o.payload==Payload::End));
    c.release_effect(end)?;
    Ok(())
}
#[test]
fn safe_fullwidth_host_profile_construction_uses_vectors_and_small_control_structs()
-> Result<(), Error> {
    let geometry = [64, 128, 1024, 1025, 4096, 512];
    let mut owner = Store::new(geometry, 8 * 1024 * 1024)?;
    let mut staging = Store::new(geometry, 8 * 1024 * 1024)?;
    let allocated = owner.allocated_bytes() + staging.allocated_bytes();
    assert!(allocated < 24 * 1024 * 1024);
    let limits = Limits {
        max_name_bytes: 65535,
        max_record_bytes: 65535,
        cname_hops: 32,
    };
    let mut core = Resolver::new(owner.buffers(), limits, 1)?;
    let mut scratch = core.make_scratch(staging.buffers())?;
    assert!(Resolver::control_bytes() < 4096);
    assert_eq!(core.byte_capacity(), 8 * 1024 * 1024);
    core.connect()?;
    core.shutdown(&mut scratch)?;
    let t = core.take_effect()?.ok_or(Error::NotReady)?;
    assert_eq!(core.effect(t)?, Effect::Stop);
    core.release_effect(t)?;
    assert_eq!(core.take_effect()?, None);
    Ok(())
}
