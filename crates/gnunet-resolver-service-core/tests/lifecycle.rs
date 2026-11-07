//! Real pure DNS/IPC types plus literal state fixtures; no OS/network/C execution.
#![expect(
    clippy::panic_in_result_fn,
    reason = "State-machine witnesses assert original identities, exact bytes, deadlines and full-state atomic errors."
)]
use gnunet_client::resolver::{Family, Request, WireId};
use gnunet_dns::{AbsoluteTime, Error, Idna, Name, Packet, RData, Record, Type};
use gnunet_dnsstub::DnsStub;
mod support;
use gnunet_types::MonoInstant;
use support::{DNS_TIMEOUT, Disposition, Effect, Memory, Output, Payload, Stage, StartQuery};
type Core<'a> = support::Core<'a, 255, 64>;
type Stub = DnsStub<8, 271, 2>;
struct LiteralIdna {
    ascii_error: Option<Error>,
    unicode_error: Option<Error>,
}
impl Idna for LiteralIdna {
    fn to_ascii(&self, input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if let Some(e) = self.ascii_error {
            return Err(e);
        }
        if !input.is_ascii() {
            return Err(Error::Unavailable);
        }
        if input.len() > out.len() {
            return Err(Error::Capacity);
        }
        out[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }
    fn to_unicode_label(&self, input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if let Some(e) = self.unicode_error {
            return Err(e);
        }
        if !input.is_ascii() {
            return Err(Error::Unavailable);
        }
        if input.len() > out.len() {
            return Err(Error::Capacity);
        }
        out[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }
}
// Fixture-only ASCII capability, deliberately rejects every non-ASCII input.
const TEXT: LiteralIdna = LiteralIdna {
    ascii_error: None,
    unicode_error: None,
};
fn utc(n: u64) -> AbsoluteTime {
    AbsoluteTime::from_micros(n)
}
fn raw(name: &'static [u8], kind: u16, value: &'static [u8]) -> Result<Record<'static>, Error> {
    Ok(Record {
        name: Name::from_wire(name)?,
        kind: Type(kind),
        class: 7,
        expiration: utc(u64::MAX),
        data: RData::Raw(value),
    })
}
fn ptr(owner: &'static [u8], target: &'static [u8], kind: u16) -> Result<Record<'static>, Error> {
    Ok(Record {
        name: Name::from_wire(owner)?,
        kind: Type(kind),
        class: 3,
        expiration: utc(u64::MAX),
        data: RData::Hostname(Name::from_wire(target)?),
    })
}
fn query(c: &mut Core) -> Result<StartQuery<255>, Error> {
    match c.take_effect() {
        Some(Effect::StartQuery(q)) => Ok(q),
        _ => Err(Error::NotReady),
    }
}
fn rows(c: &mut Core) -> Result<Vec<Output<255, 64>>, Error> {
    let mut out = Vec::new();
    while let Some(e) = c.take_effect() {
        match e {
            Effect::Output(o) => out.push(o),
            Effect::CancelQuery(_) => {}
            _ => return Err(Error::Malformed),
        }
    }
    Ok(out)
}
fn setup() -> Result<(Memory<255, 64>, Stub), Error> {
    let memory = Memory::new([3, 8, 8, 8, 32, 64], 8, 65536)?;
    let mut stub = Stub::new()?;
    stub.add_dns_ip("127.0.0.1")?;
    Ok((memory, stub))
}
fn bind<'a>(
    c: &mut Core<'a>,
    s: &mut Stage<'a>,
    stub: &mut Stub,
    q: StartQuery<255>,
    slot: u32,
) -> Result<gnunet_dnsstub::RequestId, Error> {
    let admitted = stub.resolve(q.bytes(), MonoInstant(0), |_| Ok(slot))?;
    let id = admitted.request;
    c.query_admitted(s, q.lookup, admitted)?;
    Ok(id)
}
fn send<'a>(
    c: &mut Core<'a>,
    s: &mut Stage<'a>,
    q: StartQuery<255>,
    stub: gnunet_dnsstub::RequestId,
    answers: &[Record<'_>],
    now: u64,
) -> Result<Disposition, Error> {
    c.dns_result(
        s,
        q.lookup,
        stub,
        Packet::new(
            q.bytes()[..2].try_into().map_err(|_| Error::Malformed)?,
            0,
            &[],
            answers,
            &[],
            &[],
        ),
        MonoInstant(now),
        utc(0),
        |_| Ok(2),
        &TEXT,
    )
}
#[test]
fn forward_query_literal_wire_echo_all_sections_order_and_owned_packet_storage() -> Result<(), Error>
{
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    let wire = WireId([0x12, 0x34, 0x56, 0x78]);
    let id = c
        .request(
            &mut s,
            client,
            Request::forward(wire, Family::V4, b"q")?,
            MonoInstant(0),
            utc(0),
            |bound| {
                assert_eq!(bound, 65535);
                Ok(1)
            },
            &TEXT,
        )?
        .ok_or(Error::NotReady)?;
    let q = query(&mut c)?;
    assert_eq!(q.lookup, id);
    assert_eq!(
        q.bytes(),
        b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01q\0\0\x01\0\x01"
    );
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    let answers = [raw(b"\x01q\0", 1, &[1; 4])?, raw(b"\x01q\0", 1, &[2; 4])?];
    let auth = [raw(b"\x01q\0", 1, &[3; 4])?];
    let extra = [
        raw(b"\x01q\0", 65000, b"opaque")?,
        raw(b"\x01q\0", 1, &[4; 4])?,
    ];
    c.dns_result(
        &mut s,
        id,
        token,
        Packet::new([0, 1], 0x000f, &[], &answers, &auth, &extra),
        MonoInstant(5),
        utc(0),
        |_| Ok(2),
        &TEXT,
    )?;
    assert_eq!(c.cache().record_count(), 5);
    let out = rows(&mut c)?;
    let values = out
        .iter()
        .filter_map(|o| match o.payload {
            Payload::Raw { bytes, .. } => Some(bytes[0]),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(values, vec![4, 3, 2, 1]);
    assert!(matches!(out[4].payload, Payload::End));
    assert!(out.iter().all(|o| o.client == client && o.wire_id == wire));
    let mut bytes = [0xa5; 32];
    let n = out[0].encode(&mut bytes)?;
    assert_eq!(&bytes[..n], b"\0\x0c\0\x05\x12\x34\x56\x78\x04\x04\x04\x04");
    assert_eq!(
        c.request(
            &mut s,
            client,
            Request::forward(wire, Family::V4, b"q")?,
            MonoInstant(99),
            utc(0),
            |_| Err(Error::Entropy),
            &TEXT
        )?,
        None
    );
    assert_eq!(rows(&mut c)?.len(), 5);
    Ok(())
}
#[test]
fn any_a_then_aaaa_keeps_deadline_and_defers_a_until_empty_second_response() -> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    let id = c
        .request(
            &mut s,
            client,
            Request::forward(WireId([1; 4]), Family::Any, b"q")?,
            MonoInstant(10),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?
        .ok_or(Error::NotReady)?;
    let q = query(&mut c)?;
    assert_eq!(q.kind, 1);
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    assert_eq!(
        send(
            &mut c,
            &mut s,
            q,
            token,
            &[raw(b"\x01q\0", 1, &[1; 4])?],
            100
        )?,
        Disposition::AwaitingAaaa
    );
    assert!(matches!(c.take_effect(),Some(Effect::CancelQuery(t))if t==token));
    stub.resolve_cancel(token)?;
    let aaaa = query(&mut c)?;
    assert_eq!(
        (aaaa.lookup, aaaa.kind, aaaa.deadline),
        (id, 28, MonoInstant(10 + DNS_TIMEOUT))
    );
    assert_eq!(&aaaa.bytes()[..2], &[0, 2]);
    assert_eq!(c.effect_count(), 0);
    let token2 = bind(&mut c, &mut s, &mut stub, aaaa, 0)?;
    assert_eq!(
        send(&mut c, &mut s, aaaa, token2, &[], 200)?,
        Disposition::Completed
    );
    let out = rows(&mut c)?;
    assert_eq!(out.len(), 2);
    assert!(matches!(out[0].payload, Payload::Raw { len: 4, .. }));
    assert!(matches!(out[1].payload, Payload::End));
    assert!(!c.owns_lookup(id));
    Ok(())
}
#[test]
fn any_aaaa_timeout_never_emits_cached_a_but_later_cache_request_can() -> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    let request = Request::forward(WireId([2; 4]), Family::Any, b"q")?;
    let id = c
        .request(
            &mut s,
            client,
            request,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?
        .ok_or(Error::NotReady)?;
    let q = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    send(
        &mut c,
        &mut s,
        q,
        token,
        &[raw(b"\x01q\0", 1, &[9; 4])?],
        10,
    )?;
    c.take_effect();
    let q2 = query(&mut c)?;
    bind(&mut c, &mut s, &mut stub, q2, 1)?;
    assert_eq!(c.tick(&mut s, MonoInstant(DNS_TIMEOUT - 1))?, 0);
    assert_eq!(c.effect_count(), 0);
    assert_eq!(c.tick(&mut s, MonoInstant(DNS_TIMEOUT))?, 1);
    let out = rows(&mut c)?;
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0].payload, Payload::End));
    assert_eq!(c.cache().record_count(), 1);
    assert!(!c.owns_lookup(id));
    assert_eq!(
        c.request(
            &mut s,
            client,
            request,
            MonoInstant(DNS_TIMEOUT + 1),
            utc(0),
            |_| Err(Error::Entropy),
            &TEXT
        )?,
        None
    );
    assert_eq!(rows(&mut c)?.len(), 2);
    Ok(())
}
fn empty_response<'a>(
    c: &mut Core<'a>,
    s: &mut Stage<'a>,
    q: StartQuery<255>,
    stub: gnunet_dnsstub::RequestId,
    now: u64,
) -> Result<Disposition, Error> {
    c.dns_result(
        s,
        q.lookup,
        stub,
        Packet::new(
            q.bytes()[..2].try_into().map_err(|_| Error::Malformed)?,
            0x8000,
            &[],
            &[],
            &[],
            &[],
        ),
        MonoInstant(now),
        utc(0),
        |_| Ok(2),
        &TEXT,
    )
}

#[test]
fn first_any_zero_records_still_awaits_aaaa_without_negative_cache() -> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    let wire_id = WireId([3; 4]);
    let id = c
        .request(
            &mut s,
            client,
            Request::forward(wire_id, Family::Any, b"q")?,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?
        .ok_or(Error::NotReady)?;
    let q = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    assert_eq!(
        empty_response(&mut c, &mut s, q, token, 0)?,
        Disposition::AwaitingAaaa
    );
    assert!(c.owns_lookup(id));
    assert!(matches!(c.take_effect(), Some(Effect::CancelQuery(t)) if t == token));
    stub.resolve_cancel(token)?;
    let aaaa = query(&mut c)?;
    assert_eq!(
        (aaaa.lookup, aaaa.client, aaaa.kind, aaaa.deadline),
        (id, client, 28, MonoInstant(DNS_TIMEOUT))
    );
    assert_eq!(c.effect_count(), 0);
    assert_eq!(c.cache().bucket_count(), 0);
    let token2 = bind(&mut c, &mut s, &mut stub, aaaa, 0)?;
    assert_eq!(
        empty_response(&mut c, &mut s, aaaa, token2, 1)?,
        Disposition::Completed
    );
    let out = rows(&mut c)?;
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].client, out[0].wire_id, out[0].payload),
        (client, wire_id, Payload::End)
    );
    assert!(!c.owns_lookup(id));
    assert_eq!(c.cache().bucket_count(), 0);
    Ok(())
}

#[test]
fn any_empty_a_can_return_ipv6_under_original_request_and_deadline() -> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    let wire_id = WireId([4; 4]);
    let id = c
        .request(
            &mut s,
            client,
            Request::forward(wire_id, Family::Any, b"q")?,
            MonoInstant(10),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?
        .ok_or(Error::NotReady)?;
    let q = query(&mut c)?;
    assert_eq!(q.kind, 1);
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    assert_eq!(
        empty_response(&mut c, &mut s, q, token, 100)?,
        Disposition::AwaitingAaaa
    );
    assert!(matches!(c.take_effect(), Some(Effect::CancelQuery(t)) if t == token));
    stub.resolve_cancel(token)?;
    let aaaa = query(&mut c)?;
    assert_eq!(
        (aaaa.lookup, aaaa.client, aaaa.kind, aaaa.deadline),
        (id, client, 28, MonoInstant(10 + DNS_TIMEOUT))
    );
    assert_eq!(&aaaa.bytes()[..2], &[0, 2]);
    assert_eq!(c.effect_count(), 0); // No early END or invented IPv6 value.
    let token2 = bind(&mut c, &mut s, &mut stub, aaaa, 0)?;
    let address = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let records = [Record {
        name: Name::from_wire(b"\x01q\0")?,
        kind: Type(28),
        class: 1,
        expiration: utc(5000),
        data: RData::Raw(&address),
    }];
    assert_eq!(
        c.dns_result(
            &mut s,
            aaaa.lookup,
            token2,
            Packet::new(
                aaaa.bytes()[..2].try_into().map_err(|_| Error::Malformed)?,
                0x8000,
                &[],
                &records,
                &[],
                &[]
            ),
            MonoInstant(200),
            utc(0),
            |_| Ok(3),
            &TEXT,
        )?,
        Disposition::Completed
    );
    let out = rows(&mut c)?;
    assert_eq!(out.len(), 2);
    assert_eq!((out[0].client, out[0].wire_id), (client, wire_id));
    let Payload::Raw { bytes, len } = out[0].payload else {
        return Err(Error::Malformed);
    };
    assert_eq!((len, &bytes[..len]), (16, address.as_slice()));
    assert_eq!(
        (out[1].client, out[1].wire_id, out[1].payload),
        (client, wire_id, Payload::End)
    );
    assert!(!c.owns_lookup(id));
    Ok(())
}
#[test]
fn cname_ignores_record_owner_for_redirect_restarts_deadline_and_retires_old_generation()
-> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([4; 4]), Family::V4, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let old = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, old, 0)?;
    send(
        &mut c,
        &mut s,
        old,
        token,
        &[ptr(b"\x07foreign\0", b"\x06target\0", 5)?],
        1_000_000,
    )?;
    assert!(matches!(c.take_effect(),Some(Effect::CancelQuery(t))if t==token));
    let next = query(&mut c)?;
    assert_eq!(next.hostname.bytes(), b"target");
    assert_ne!(next.lookup, old.lookup);
    assert_eq!(next.deadline, MonoInstant(31_000_000));
    assert!(!c.owns_lookup(old.lookup));
    assert!(c.owns_lookup(next.lookup));
    assert_eq!(
        c.malformed_dns(old.lookup, token),
        Err(Error::StaleGeneration)
    );
    Ok(())
}
#[test]
fn v6_and_ptr_generate_correct_questions_and_reverse_payload_is_native_name() -> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([5; 4]), Family::V6, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let six = query(&mut c)?;
    assert_eq!(six.kind, 28);
    assert_eq!(&six.bytes()[six.bytes().len() - 4..], b"\0\x1c\0\x01");
    bind(&mut c, &mut s, &mut stub, six, 0)?;
    let wire = WireId([7, 0, 8, 0]);
    c.request(
        &mut s,
        client,
        Request::reverse(wire, core::net::Ipv4Addr::LOCALHOST.into()),
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let reverse = query(&mut c)?;
    assert_eq!(
        (reverse.hostname.bytes(), reverse.kind),
        (b"1.0.0.127.in-addr.arpa".as_slice(), 12)
    );
    let token = bind(&mut c, &mut s, &mut stub, reverse, 1)?;
    send(
        &mut c,
        &mut s,
        reverse,
        token,
        &[ptr(
            b"\x011\x010\x010\x03127\x07in-addr\x04arpa\0",
            b"\x04host\x06native\0",
            12,
        )?],
        0,
    )?;
    let out = rows(&mut c)?;
    assert_eq!(out.len(), 2);
    let mut frame = [0; 64];
    let n = out[0].encode(&mut frame)?;
    assert_eq!(&frame[..n], b"\0\x14\0\x05\x07\0\x08\0host.native\0");
    Ok(())
}
#[test]
fn duplicate_wire_ids_are_independent_and_eof_only_cancels_original_client() -> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let first = c.connect()?;
    let other = c.connect()?;
    let wire = WireId([0xde, 0xad, 0xbe, 0xef]);
    for name in [b"a".as_slice(), b"b"] {
        c.request(
            &mut s,
            first,
            Request::forward(wire, Family::V4, name)?,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?;
    }
    let a = query(&mut c)?;
    let ta = bind(&mut c, &mut s, &mut stub, a, 0)?;
    let b = query(&mut c)?;
    assert_ne!(a.lookup, b.lookup);
    bind(&mut c, &mut s, &mut stub, b, 1)?;
    c.request(
        &mut s,
        other,
        Request::forward(wire, Family::V4, b"c")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    let tc = bind(&mut c, &mut s, &mut stub, q, 2)?;
    send(&mut c, &mut s, a, ta, &[raw(b"\x01a\0", 1, &[1; 4])?], 1)?;
    let out = rows(&mut c)?;
    assert_eq!(out[0].wire_id, wire);
    assert!(c.owns_lookup(b.lookup));
    c.disconnect(&mut s, first)?;
    assert!(!c.owns_client(first));
    assert!(!c.owns_lookup(b.lookup));
    assert!(c.owns_lookup(q.lookup));
    assert_eq!(c.lookup_stub(q.lookup)?, Some(tc));
    assert_eq!(c.cache().record_count(), 1);
    let replacement = c.connect()?;
    assert_eq!(replacement.resource_id().index, first.resource_id().index);
    assert_ne!(replacement, first);
    assert_eq!(c.malformed_dns(a.lookup, ta), Err(Error::StaleGeneration));
    Ok(())
}
#[test]
fn stub_eviction_detaches_old_timeout_so_it_cannot_cancel_new_slot_owner() -> Result<(), Error> {
    let (mut memory, _stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let mut stub = DnsStub::<1, 271, 1>::new()?;
    stub.add_dns_ip("127.0.0.1")?;
    let client = c.connect()?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([1; 4]), Family::V4, b"a")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let old = query(&mut c)?;
    let a = stub.resolve(old.bytes(), MonoInstant(0), |_| Ok(0))?;
    let old_token = a.request;
    c.query_admitted(&mut s, old.lookup, a)?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([2; 4]), Family::V4, b"b")?,
        MonoInstant(5),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let new = query(&mut c)?;
    let a = stub.resolve(new.bytes(), MonoInstant(5), |_| Ok(0))?;
    assert_eq!(a.evicted, Some(old_token));
    let new_token = a.request;
    c.query_admitted(&mut s, new.lookup, a)?;
    assert_eq!(c.lookup_stub(old.lookup)?, None);
    assert_eq!(c.lookup_stub(new.lookup)?, Some(new_token));
    assert_eq!(
        c.malformed_dns(old.lookup, old_token),
        Err(Error::StaleGeneration)
    );
    assert_eq!(c.tick(&mut s, MonoInstant(DNS_TIMEOUT))?, 1);
    assert!(matches!(
        c.take_effect(),
        Some(Effect::Output(Output {
            wire_id: WireId([1, 1, 1, 1]),
            payload: Payload::End,
            ..
        }))
    ));
    assert_eq!(c.take_effect(), None);
    assert!(stub.owns_request(new_token));
    assert_eq!(c.lookup_stub(new.lookup)?, Some(new_token));
    Ok(())
}
#[test]
fn no_server_waits_full_deadline_and_unknown_or_malformed_dns_is_nonterminal() -> Result<(), Error>
{
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([1; 4]), Family::V4, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    c.query_unavailable(&mut s, q.lookup)?;
    assert_eq!(c.tick(&mut s, MonoInstant(DNS_TIMEOUT - 1))?, 0);
    assert_eq!(c.take_effect(), None);
    assert_eq!(c.tick(&mut s, MonoInstant(DNS_TIMEOUT))?, 1);
    assert_eq!(rows(&mut c)?.len(), 1);
    c.request(
        &mut s,
        client,
        Request::forward(WireId([2; 4]), Family::V4, b"q")?,
        MonoInstant(DNS_TIMEOUT),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    let mut before = _baseline;
    c.copy_logical_state_to(&mut before)?;
    assert_eq!(c.malformed_dns(q.lookup, token)?, Disposition::Ignored);
    assert_eq!(
        c.dns_result(
            &mut s,
            q.lookup,
            token,
            Packet::new([9, 9], 0, &[], &[], &[], &[]),
            MonoInstant(99),
            utc(0),
            |_| Ok(1),
            &TEXT
        )?,
        Disposition::Ignored
    );
    assert!(c == before);
    Ok(())
}

#[test]
fn capability_entropy_clock_record_capacity_failures_leave_entire_owner_unchanged()
-> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    let request = Request::forward(WireId([1; 4]), Family::V4, b"q")?;
    let mut before = _baseline;
    c.copy_logical_state_to(&mut before)?;
    assert_eq!(
        c.request(
            &mut s,
            client,
            request,
            MonoInstant(0),
            utc(0),
            |_| Err(Error::Entropy),
            &TEXT
        ),
        Err(Error::Entropy)
    );
    assert!(c == before);
    assert_eq!(
        c.request(
            &mut s,
            client,
            request,
            MonoInstant(0),
            utc(0),
            |_| Ok(65535),
            &TEXT
        ),
        Err(Error::InvalidInput)
    );
    assert!(c == before);
    let unavailable = LiteralIdna {
        ascii_error: Some(Error::Unavailable),
        unicode_error: None,
    };
    assert_eq!(
        c.request(
            &mut s,
            client,
            request,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &unavailable
        ),
        Err(Error::Unavailable)
    );
    assert!(c == before);
    assert_eq!(
        c.request(
            &mut s,
            client,
            request,
            MonoInstant(u64::MAX),
            utc(0),
            |_| Ok(1),
            &TEXT
        ),
        Err(Error::Overflow)
    );
    assert!(c == before);
    c.request(
        &mut s,
        client,
        request,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    c.copy_logical_state_to(&mut before)?;
    let too_large = [raw(b"\x01q\0", 1, &[1; 65])?];
    assert_eq!(
        send(&mut c, &mut s, q, token, &too_large, 1),
        Err(Error::Capacity)
    );
    assert!(c == before);
    let too_many = [raw(b"\x01q\0", 1, &[1; 4])?; 33];
    assert_eq!(
        send(&mut c, &mut s, q, token, &too_many, 1),
        Err(Error::Capacity)
    );
    assert!(c == before);
    assert!(s != before); // this refusal follows32 staged inserts; scratch is dirty
    let response = [raw(b"\x01q\0", 1, &[1; 4])?];
    let unavailable = LiteralIdna {
        ascii_error: None,
        unicode_error: Some(Error::Unavailable),
    };
    assert_eq!(
        c.dns_result(
            &mut s,
            q.lookup,
            token,
            Packet::new([0, 1], 0, &[], &response, &[], &[]),
            MonoInstant(1),
            utc(0),
            |_| Ok(2),
            &unavailable
        ),
        Err(Error::Unavailable)
    );
    assert!(c == before);
    assert!(c.owns_lookup(q.lookup));
    Ok(())
}
#[test]
fn output_queue_and_host_storage_reject_atomically_without_losing_original_completion()
-> Result<(), Error> {
    let mut memory = Memory::<255, 16>::new([1, 2, 1, 2, 2, 1], 4, 65536)?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let mut before = _baseline;

    let client = c.connect()?;
    c.load_machine_files(&mut s, b"127.0.0.1 one\n", b"")?;
    c.copy_logical_state_to(&mut before)?;
    assert_eq!(
        c.load_machine_files(&mut s, b"127.0.0.2 two\n", b""),
        Err(Error::Capacity)
    );
    assert!(c == before);
    c.request(
        &mut s,
        client,
        Request::forward(WireId([1; 4]), Family::V4, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let Some(Effect::StartQuery(q)) = c.take_effect() else {
        return Err(Error::NotReady);
    };
    let mut stub = DnsStub::<1, 271, 1>::new()?;
    stub.add_dns_ip("127.0.0.1")?;
    let a = stub.resolve(q.bytes(), MonoInstant(0), |_| Ok(0))?;
    let token = a.request;
    c.query_admitted(&mut s, q.lookup, a)?;
    c.copy_logical_state_to(&mut before)?;
    // One Cancel + one VALUE + END cannot fit E=1. No terminal or cache is lost.
    let records = [raw(b"\x01q\0", 1, &[1; 4])?];
    assert_eq!(
        c.dns_result(
            &mut s,
            q.lookup,
            token,
            Packet::new([0, 1], 0, &[], &records, &[], &[]),
            MonoInstant(1),
            utc(0),
            |_| Ok(1),
            &TEXT
        ),
        Err(Error::Capacity)
    );
    assert!(c == before);
    assert_eq!(c.effect_count(), 0);
    assert_eq!(c.cache().record_count(), 0);
    assert!(c.owns_lookup(q.lookup));
    // Cleanup has a reserved L-token queue. Even E=1 can finish its timer after
    // oversized result refusal, without losing either cancel or terminal output.
    assert_eq!(c.tick(&mut s, MonoInstant(DNS_TIMEOUT))?, 1);
    assert_eq!(c.pending_cleanups(), 1);
    assert!(matches!(c.take_effect(),Some(Effect::CancelQuery(t)) if t==token));
    assert!(matches!(
        c.take_effect(),
        Some(Effect::Output(Output {
            payload: Payload::End,
            ..
        }))
    ));
    assert!(!c.owns_lookup(q.lookup));
    c.shutdown(&mut s)?;
    assert_eq!(c.take_effect(), Some(Effect::Stop));
    assert!(c.is_closed());
    Ok(())
}
#[test]
fn malformed_query_content_ends_but_aaaa_pack_failure_returns_previously_cached_a()
-> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    let bad = LiteralIdna {
        ascii_error: Some(Error::Malformed),
        unicode_error: None,
    };
    assert_eq!(
        c.request(
            &mut s,
            client,
            Request::forward(WireId([1; 4]), Family::V4, b"bad")?,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &bad
        )?,
        None
    );
    assert!(matches!(rows(&mut c)?[0].payload, Payload::End));
    assert_eq!(c.lookup_count(), 0);
    c.request(
        &mut s,
        client,
        Request::forward(WireId([2; 4]), Family::Any, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    let records = [raw(b"\x01q\0", 1, &[6; 4])?];
    assert_eq!(
        c.dns_result(
            &mut s,
            q.lookup,
            token,
            Packet::new([0, 1], 0, &[], &records, &[], &[]),
            MonoInstant(1),
            utc(0),
            |_| Ok(2),
            &bad
        )?,
        Disposition::Completed
    );
    let out = rows(&mut c)?;
    assert_eq!(out.len(), 2);
    assert!(matches!(out[0].payload, Payload::Raw { len: 4, .. }));
    Ok(())
}
#[test]
fn packet_arena_input_can_be_reused_and_utc_expiry_equality_remains_valid() -> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    let request = Request::forward(WireId([1; 4]), Family::V4, b"q")?;
    c.request(
        &mut s,
        client,
        request,
        MonoInstant(0),
        utc(7),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    let mut input=*b"\0\x01\x81\x80\0\x01\0\x01\0\0\0\0\x01q\0\0\x01\0\x01\xc0\x0c\0\x01\0\x01\0\0\0\x01\0\x04\x07\x08\x09\x0a";
    let mut storage = [0; 512];
    {
        let mut arena = gnunet_dns::Arena::new(&mut storage);
        let mut queries = [gnunet_dns::Query::EMPTY; 1];
        let mut records = [Record::EMPTY; 1];
        let packet = Packet::parse(
            &input,
            utc(7),
            &mut arena,
            &mut queries,
            &mut records,
            gnunet_dns::Limits::DNS,
        )?;
        input.fill(0);
        c.dns_result(
            &mut s,
            q.lookup,
            token,
            packet,
            MonoInstant(1),
            utc(7),
            |_| Ok(2),
            &TEXT,
        )?;
    }
    storage.fill(0);
    let first = rows(&mut c)?;
    assert!(matches!(first[0].payload,Payload::Raw{bytes,len:4}if bytes[..4]==[7,8,9,10]));
    assert_eq!(
        c.request(
            &mut s,
            client,
            request,
            MonoInstant(2),
            utc(1_000_007),
            |_| Err(Error::Entropy),
            &TEXT
        )?,
        None
    );
    assert_eq!(rows(&mut c)?.len(), 2);
    assert!(
        c.request(
            &mut s,
            client,
            request,
            MonoInstant(3),
            utc(1_000_008),
            |_| Ok(3),
            &TEXT
        )?
        .is_some()
    );
    assert_eq!(c.cache().bucket_count(), 0);
    Ok(())
}
#[test]
fn bounded_cname_cycle_rejects_without_partial_cache_or_result_success() -> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([1; 4]), Family::V4, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    let mut before = _baseline;
    c.copy_logical_state_to(&mut before)?;
    assert_eq!(
        send(
            &mut c,
            &mut s,
            q,
            token,
            &[ptr(b"\x07foreign\0", b"\x01q\0", 5)?],
            1
        ),
        Err(Error::Capacity)
    );
    assert!(c == before);
    assert!(c.owns_lookup(q.lookup));
    assert_eq!(c.cache().record_count(), 0);
    Ok(())
}
#[test]
fn immediate_default_and_explicit_soft_follow_client_lifetime_not_lookup_count() -> Result<(), Error>
{
    let (mut memory, _stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    c.begin_soft_shutdown(&mut s)?;
    assert_eq!(c.connect(), Err(Error::Closed));
    assert!(!c.is_closed()); // no active lookup does not end a connected client
    c.load_machine_files(&mut s, b"127.0.0.1 cached\n", b"")?;
    assert_eq!(
        c.request(
            &mut s,
            client,
            Request::forward(WireId([1; 4]), Family::V4, b"cached")?,
            MonoInstant(0),
            utc(0),
            |_| Err(Error::Entropy),
            &TEXT
        )?,
        None
    );
    rows(&mut c)?;
    assert!(!c.is_closed());
    c.disconnect(&mut s, client)?;
    assert_eq!(c.take_effect(), Some(Effect::Stop));
    assert!(c.is_closed());
    let (mut memory, _stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([2; 4]), Family::V4, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    c.shutdown(&mut s)?;
    assert!(!c.owns_client(client));
    assert_eq!(c.lookup_count(), 0);
    assert_eq!(c.take_effect(), Some(Effect::Stop));
    assert_eq!(c.take_effect(), None);
    c.shutdown(&mut s)?;
    assert_eq!(c.take_effect(), None);
    Ok(())
}
#[test]
fn long_name_drops_only_original_client_and_long_search_falls_back_without_copy_error()
-> Result<(), Error> {
    let mut memory = Memory::<300, 16>::new([2, 2, 2, 2, 4, 8], 4, 65536)?;
    let (mut c, mut s, _baseline) = memory.views(1)?;

    let client = c.connect()?;
    let other = c.connect()?;
    c.set_search(&mut s, Some(&[b's'; 512]))?;
    c.request(
        &mut s,
        other,
        Request::forward(WireId([1; 4]), Family::V4, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let Some(Effect::StartQuery(q)) = c.take_effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(q.hostname.bytes(), b"q");
    // This fixture has no host/upstream; report the actual pure-stub admission
    // failure before allowing another client's event to advance.
    let mut no_server = gnunet_dnsstub::DnsStub::<1, 271, 1>::new()?;
    assert!(matches!(
        no_server.resolve(q.bytes(), MonoInstant(0), |_| Ok(0)),
        Err(Error::Unavailable)
    ));
    c.query_unavailable(&mut s, q.lookup)?;
    assert_eq!(
        c.request(
            &mut s,
            client,
            Request::forward(WireId([2; 4]), Family::V4, &[b'x'; 255])?,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT
        )?,
        None
    );
    assert!(
        matches!(c.take_effect(),Some(Effect::DropClient{client:id,reason:Error::TooLarge})if id==client)
    );
    assert!(c.owns_client(other));
    assert!(c.owns_lookup(q.lookup));
    assert!(!c.owns_client(client));
    Ok(())
}
#[test]
fn forged_raw_output_length_is_rejected_before_any_frame_byte_changes() -> Result<(), Error> {
    // The historical independently forgeable (bytes,len) no longer exists in the
    // production API. Exercise its stronger borrowed-slice replacement directly.
    let mut store = support::Store::new([1, 1, 0, 1, 1, 1], 128)?;
    let mut c = gnunet_resolver_service_core::owner::Resolver::new(
        store.buffers(),
        gnunet_resolver_service_core::storage::Limits {
            max_name_bytes: 255,
            max_record_bytes: 65535,
            cname_hops: 8,
        },
        1,
    )?;
    let client = c.connect()?;
    let large = vec![7; 65528];
    let out = gnunet_resolver_service_core::owner::Output {
        client,
        wire_id: WireId([1; 4]),
        payload: gnunet_resolver_service_core::owner::Payload::Raw(&large),
    };
    let mut bytes = [0xa5; 32];
    assert_eq!(out.encode(&mut bytes), Err(Error::TooLarge));
    assert_eq!(bytes, [0xa5; 32]);
    let short = gnunet_resolver_service_core::owner::Output {
        payload: gnunet_resolver_service_core::owner::Payload::Raw(&[7; 25]),
        ..out
    };
    assert_eq!(short.encode(&mut bytes), Err(Error::Capacity));
    assert_eq!(bytes, [0xa5; 32]);
    let maximum = vec![9; 65527];
    let legal = gnunet_resolver_service_core::owner::Output {
        payload: gnunet_resolver_service_core::owner::Payload::Raw(&maximum),
        ..out
    };
    let mut frame = vec![0; 65535];
    assert_eq!(legal.encode(&mut frame)?, 65535);
    assert_eq!(&frame[..8], &[255, 255, 0, 5, 1, 1, 1, 1]);
    assert_eq!(&frame[8..], maximum);
    Ok(())
}

#[test]
fn client_lookup_and_effect_admission_refusals_preserve_all_original_generations()
-> Result<(), Error> {
    let mut memory = Memory::<64, 16>::new([1, 2, 0, 2, 2, 1], 4, 65536)?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let mut before = _baseline;

    let client = c.connect()?;
    assert_eq!(c.connect(), Err(Error::Capacity));
    let req = Request::forward(WireId([1; 4]), Family::V4, b"q")?;
    let first = c
        .request(
            &mut s,
            client,
            req,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?
        .ok_or(Error::NotReady)?;
    c.copy_logical_state_to(&mut before)?;
    assert_eq!(
        c.request(
            &mut s,
            client,
            req,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT
        ),
        Err(Error::Capacity)
    );
    assert!(c == before);
    assert!(matches!(c.take_effect(),Some(Effect::StartQuery(q))if q.lookup==first));
    let second = c
        .request(
            &mut s,
            client,
            req,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?
        .ok_or(Error::NotReady)?;
    assert_eq!(
        (second.resource_id().index, second.resource_id().generation),
        (1, 0)
    );
    c.copy_logical_state_to(&mut before)?;
    assert_eq!(
        c.request(
            &mut s,
            client,
            req,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT
        ),
        Err(Error::Capacity)
    );
    assert!(c == before);
    c.disconnect(&mut s, client)?;
    assert_eq!(c.take_effect(), None);
    let new = c.connect()?;
    assert_eq!(
        (new.resource_id().index, new.resource_id().generation),
        (0, 1)
    );
    assert_eq!(
        c.request(
            &mut s,
            client,
            req,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT
        ),
        Err(Error::StaleGeneration)
    );
    assert!(c.owns_client(new));
    Ok(())
}
#[test]
fn any_second_phase_capability_failure_keeps_original_a_owner_and_cache_unmodified()
-> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([1; 4]), Family::Any, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    let mut before = _baseline;
    c.copy_logical_state_to(&mut before)?;
    let records = [raw(b"\x01q\0", 1, &[1; 4])?];
    let missing = LiteralIdna {
        ascii_error: Some(Error::Unavailable),
        unicode_error: None,
    };
    assert_eq!(
        c.dns_result(
            &mut s,
            q.lookup,
            token,
            Packet::new([0, 1], 0, &[], &records, &[], &[]),
            MonoInstant(5),
            utc(0),
            |_| Ok(2),
            &missing
        ),
        Err(Error::Unavailable)
    );
    assert!(c == before);
    assert_eq!(c.lookup_stub(q.lookup)?, Some(token));
    assert_eq!(c.cache().record_count(), 0);
    assert_eq!(c.effect_count(), 0);
    Ok(())
}
#[test]
fn hosts_hit_precedes_service_name_255_limit_and_unknown_raw_address_is_not_repaired()
-> Result<(), Error> {
    let mut memory = Memory::<300, 16>::new([1, 2, 2, 2, 4, 8], 4, 65536)?;
    let (mut c, mut s, _baseline) = memory.views(1)?;

    let client = c.connect()?;
    let mut hosts = b"127.0.0.1 ".to_vec();
    hosts.extend_from_slice(&[b'x'; 255]);
    hosts.push(b'\n');
    c.load_machine_files(&mut s, &hosts, b"")?;
    assert_eq!(
        c.request(
            &mut s,
            client,
            Request::forward(WireId([1; 4]), Family::V4, &[b'x'; 255])?,
            MonoInstant(0),
            utc(0),
            |_| Err(Error::Entropy),
            &TEXT
        )?,
        None
    );
    assert!(c.owns_client(client));
    assert!(matches!(
        c.take_effect(),
        Some(Effect::Output(Output {
            payload: Payload::Raw { len: 4, .. },
            ..
        }))
    ));
    assert!(matches!(
        c.take_effect(),
        Some(Effect::Output(Output {
            payload: Payload::End,
            ..
        }))
    ));
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([2; 4]), Family::V4, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    send(&mut c, &mut s, q, token, &[raw(b"\x01q\0", 1, &[1; 3])?], 1)?;
    let out = rows(&mut c)?;
    assert!(matches!(out[0].payload, Payload::Raw { len: 3, .. }));
    let mut bytes = [0; 32];
    let n = out[0].encode(&mut bytes)?;
    let frame = gnunet_wire::official::Frame::decode(&bytes[..n])?;
    assert_eq!(
        gnunet_client::resolver::Response::decode(frame)?.address(),
        Err(Error::Malformed)
    );
    Ok(())
}

#[test]
fn nonempty_aaaa_yields_newest_v6_before_old_v4_and_any_cname_waits_for_second_phase()
-> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([1; 4]), Family::Any, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    let token = bind(&mut c, &mut s, &mut stub, q, 0)?;
    send(&mut c, &mut s, q, token, &[raw(b"\x01q\0", 1, &[4; 4])?], 1)?;
    assert!(matches!(c.take_effect(), Some(Effect::CancelQuery(_))));
    let q2 = query(&mut c)?;
    let t2 = bind(&mut c, &mut s, &mut stub, q2, 1)?;
    send(&mut c, &mut s, q2, t2, &[raw(b"\x01q\0", 28, &[6; 16])?], 2)?;
    let out = rows(&mut c)?;
    assert!(matches!(out[0].payload, Payload::Raw { len: 16, .. }));
    assert!(matches!(out[1].payload, Payload::Raw { len: 4, .. }));
    assert!(matches!(out[2].payload, Payload::End));
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    c.request(
        &mut s,
        client,
        Request::forward(WireId([2; 4]), Family::Any, b"q")?,
        MonoInstant(0),
        utc(0),
        |_| Ok(1),
        &TEXT,
    )?;
    let q = query(&mut c)?;
    let t = bind(&mut c, &mut s, &mut stub, q, 0)?;
    send(
        &mut c,
        &mut s,
        q,
        t,
        &[ptr(b"\x07foreign\0", b"\x06target\0", 5)?],
        1,
    )?;
    c.take_effect();
    let q2 = query(&mut c)?;
    assert_eq!((q2.lookup, q2.kind), (q.lookup, 28));
    let t2 = bind(&mut c, &mut s, &mut stub, q2, 1)?;
    send(&mut c, &mut s, q2, t2, &[], 1_000_000)?;
    assert!(matches!(c.take_effect(), Some(Effect::CancelQuery(_))));
    let target = query(&mut c)?;
    assert_ne!(target.lookup, q.lookup);
    assert_eq!(
        (target.hostname.bytes(), target.kind, target.deadline),
        (b"target".as_slice(), 1, MonoInstant(31_000_000))
    );
    Ok(())
}

#[test]
fn same_deadline_many_lookups_make_bounded_progress_after_draining_e2() -> Result<(), Error> {
    let mut memory = Memory::<64, 16>::new([1, 4, 0, 4, 4, 2], 4, 65536)?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let mut before = _baseline;

    let client = c.connect()?;
    let mut stub = DnsStub::<4, 271, 1>::new()?;
    stub.add_dns_ip("127.0.0.1")?;
    for slot in 0..4 {
        c.request(
            &mut s,
            client,
            Request::forward(WireId([slot as u8; 4]), Family::V4, b"q")?,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?;
        let Some(Effect::StartQuery(q)) = c.take_effect() else {
            return Err(Error::NotReady);
        };
        let a = stub.resolve(q.bytes(), MonoInstant(0), |_| Ok(slot))?;
        c.query_admitted(&mut s, q.lookup, a)?;
    }
    assert_eq!(c.next_wakeup(), Some(MonoInstant(DNS_TIMEOUT)));
    assert_eq!(c.tick(&mut s, MonoInstant(DNS_TIMEOUT))?, 1);
    assert_eq!(c.tick(&mut s, MonoInstant(DNS_TIMEOUT))?, 1);
    assert_eq!(
        (c.pending_cleanups(), c.effect_count(), c.lookup_count()),
        (2, 4, 2)
    );
    c.copy_logical_state_to(&mut before)?;
    assert_eq!(
        c.tick(&mut s, MonoInstant(DNS_TIMEOUT)),
        Err(Error::Capacity)
    );
    assert!(c == before);
    assert_eq!(c.next_wakeup(), Some(MonoInstant(DNS_TIMEOUT)));
    let mut ended = Vec::new();
    let mut cancelled = 0;
    while let Some(e) = c.take_effect() {
        match e {
            Effect::CancelQuery(t) => {
                stub.resolve_cancel(t)?;
                cancelled += 1
            }
            Effect::Output(Output {
                wire_id,
                payload: Payload::End,
                ..
            }) => ended.push(wire_id),
            _ => return Err(Error::Malformed),
        }
    }
    for _ in 0..2 {
        assert_eq!(c.tick(&mut s, MonoInstant(DNS_TIMEOUT))?, 1);
    }
    while let Some(e) = c.take_effect() {
        match e {
            Effect::CancelQuery(t) => {
                stub.resolve_cancel(t)?;
                cancelled += 1
            }
            Effect::Output(Output {
                wire_id,
                payload: Payload::End,
                ..
            }) => ended.push(wire_id),
            _ => return Err(Error::Malformed),
        }
    }
    assert_eq!(
        ended,
        vec![
            WireId([0; 4]),
            WireId([1; 4]),
            WireId([2; 4]),
            WireId([3; 4])
        ]
    );
    assert_eq!(cancelled, 4);
    assert_eq!(c.lookup_count(), 0);
    assert_eq!(c.next_wakeup(), None);
    Ok(())
}
#[test]
fn eof_four_actual_stub_associations_revokes_client_immediately_with_e2_and_reuse_is_safe()
-> Result<(), Error> {
    let mut memory = Memory::<64, 16>::new([1, 4, 0, 4, 4, 2], 4, 65536)?;
    let (mut c, mut s, _baseline) = memory.views(1)?;

    let client = c.connect()?;
    let mut stub = DnsStub::<4, 271, 1>::new()?;
    stub.add_dns_ip("127.0.0.1")?;
    let mut old = Vec::new();
    for slot in 0..4 {
        c.request(
            &mut s,
            client,
            Request::forward(WireId([slot as u8; 4]), Family::V4, b"q")?,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?;
        let Some(Effect::StartQuery(q)) = c.take_effect() else {
            return Err(Error::NotReady);
        };
        let a = stub.resolve(q.bytes(), MonoInstant(0), |_| Ok(slot))?;
        old.push((q.lookup, a.request));
        c.query_admitted(&mut s, q.lookup, a)?;
    }
    c.disconnect(&mut s, client)?;
    assert!(!c.owns_client(client));
    assert_eq!(c.lookup_count(), 0);
    assert_eq!(c.pending_cleanups(), 4);
    for (id, token) in &old {
        assert_eq!(c.malformed_dns(*id, *token), Err(Error::StaleGeneration));
    }
    let new = c.connect()?;
    assert_ne!(client, new);
    let id = c
        .request(
            &mut s,
            new,
            Request::forward(WireId([9; 4]), Family::V4, b"new")?,
            MonoInstant(1),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?
        .ok_or(Error::NotReady)?;
    // Existing cleanup cannot be starved or mistaken for the replacement generation.
    for expected in old.iter().rev() {
        assert!(matches!(c.take_effect(),Some(Effect::CancelQuery(t))if t==expected.1));
        stub.resolve_cancel(expected.1)?;
    }
    let Some(Effect::StartQuery(q)) = c.take_effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(q.lookup, id);
    let a = stub.resolve(q.bytes(), MonoInstant(1), |_| Ok(0))?;
    let current = a.request;
    c.query_admitted(&mut s, id, a)?;
    assert_eq!(c.lookup_stub(id)?, Some(current));
    for (oldid, token) in old {
        assert_eq!(c.malformed_dns(oldid, token), Err(Error::StaleGeneration));
    }
    assert!(stub.owns_request(current));
    assert_eq!(c.pending_cleanups(), 0);
    Ok(())
}
#[test]
fn actual_admission_cannot_be_reported_before_start_effect_was_emitted() -> Result<(), Error> {
    let (mut memory, mut stub) = setup()?;
    let (mut c, mut s, _baseline) = memory.views(1)?;
    let client = c.connect()?;
    let id = c
        .request(
            &mut s,
            client,
            Request::forward(WireId([1; 4]), Family::V4, b"q")?,
            MonoInstant(0),
            utc(0),
            |_| Ok(1),
            &TEXT,
        )?
        .ok_or(Error::NotReady)?;
    let a = stub.resolve(b"ordinary fixture", MonoInstant(0), |_| Ok(0))?;
    let token = a.request;
    let mut before = _baseline;
    c.copy_logical_state_to(&mut before)?;
    assert_eq!(c.query_admitted(&mut s, id, a), Err(Error::InvalidInput));
    assert!(c == before);
    assert_eq!(c.query_unavailable(&mut s, id), Err(Error::InvalidInput));
    assert!(c == before);
    stub.resolve_cancel(token)?;
    let q = query(&mut c)?;
    assert_eq!(q.lookup, id);
    bind(&mut c, &mut s, &mut stub, q, 0)?;
    assert!(c.lookup_stub(id)?.is_some());
    Ok(())
}
