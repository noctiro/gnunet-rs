//! Independent layout, normal C trace and lifecycle boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify externally defined protocol and state transitions."
)]
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use gnunet_client::{
    resolver::{self, Family, FamilyProfile, Query, Reply, Request, Response, WireId},
    resolver_handle::{Completion, ConnectionEpoch, Event, Hostname, RequestId, ResolverHandle},
};
use gnunet_types::{AbsoluteTime, Duration, Error};
use gnunet_wire::official::{Frame, MessageHeader, message_type};
type TestResult = Result<(), Error>;
const P: FamilyProfile = FamilyProfile::DARWIN;
const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
fn remote<const R: usize, const N: usize>(
    h: &mut ResolverHandle<R, N>,
    name: &[u8],
    timeout: u64,
) -> Result<RequestId, Error> {
    h.ip_get(
        name,
        Family::Any,
        Duration(timeout),
        AbsoluteTime::from_micros(0),
    )
}
fn start<const R: usize, const N: usize>(
    h: &mut ResolverHandle<R, N>,
    now: u64,
    out: &mut [u8],
) -> Result<(ConnectionEpoch, WireId), Error> {
    let e = h.begin_connection(AbsoluteTime::from_micros(now))?;
    let q = h.next_request(e, out, AbsoluteTime::from_micros(now))?;
    Ok((e, q.wire_id))
}
fn reply(id: WireId, value: Reply<'_>, out: &mut [u8]) -> Result<usize, Error> {
    resolver::encode_response(id, value, out)
}
#[test]
fn normal_c_daemon_wire_trace_has_native_family_and_opaque_id() -> TestResult {
    // Actual normal C daemon probe-results3/wire-unspec.stdout, v0.29.1.
    let expected = [
        0, 26, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, b'l', b'o', b'c', b'a', b'l',
        b'h', b'o', b's', b't', 0,
    ];
    let id = WireId([0x78, 0x56, 0x34, 0x12]);
    let q = Request::forward(id, Family::Any, b"localhost")?;
    let mut b = [0; 64];
    let n = q.encode(P, &mut b)?;
    assert_eq!(&b[..n], expected);
    let decoded = Request::decode(Frame::decode(&expected)?, P)?;
    assert_eq!(decoded.id(), id);
    assert_eq!(
        decoded.query(),
        Query::Forward {
            family: Family::Any,
            hostname: b"localhost"
        }
    );
    let response = [
        0, 24, 0, 5, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    assert_eq!(
        Response::decode(Frame::decode(&response)?)?.address()?,
        Some(V6)
    );
    let n = reply(id, Reply::Address(V6), &mut b)?;
    assert_eq!(&b[..n], response);
    let reverse = [
        0, 20, 0, 4, 0, 0, 0, 1, 0, 0, 0, 2, 0x78, 0x56, 0x34, 0x12, 127, 0, 0, 1,
    ];
    let n = Request::reverse(id, V4).encode(P, &mut b)?;
    assert_eq!(&b[..n], reverse);
    assert_eq!(
        Request::decode(Frame::decode(&reverse)?, P)?.query(),
        Query::Reverse(V4)
    );
    Ok(())
}
#[test]
fn maximum_65535_frame_is_legal_but_65536_is_rejected_atomically() -> TestResult {
    let name = vec![b'a'; 65_518];
    let mut b = vec![0xA5; 65_536];
    let q = Request::forward(WireId([1, 2, 3, 4]), Family::V4, &name)?;
    assert_eq!(q.encoded_len()?, 65_535);
    assert_eq!(q.encode(P, &mut b)?, 65_535);
    assert_eq!(b[65_535], 0xA5);
    assert_eq!(
        Request::decode(Frame::decode(&b[..65_535])?, P)?.query(),
        Query::Forward {
            family: Family::V4,
            hostname: &name
        }
    );
    let too_long = vec![b'a'; 65_519];
    assert_eq!(
        Request::forward(WireId([0; 4]), Family::Any, &too_long),
        Err(Error::TooLarge)
    );
    let mut small = [0xA5; 17];
    assert_eq!(q.encode(P, &mut small), Err(Error::Capacity));
    assert_eq!(small, [0xA5; 17]);
    Ok(())
}
#[test]
fn codec_rejects_wrong_types_truncation_family_and_name_without_partial_writes() -> TestResult {
    assert_eq!(FamilyProfile::new(2, 2), Err(Error::InvalidInput));
    assert_eq!(P.encode(Family::V6), 30);
    assert_eq!(FamilyProfile::LINUX.encode(Family::V6), 10);
    let mut b = [0xA5; 64];
    let q = Request::forward(WireId([9; 4]), Family::V6, b"name")?;
    let n = q.encode(P, &mut b)?;
    assert_eq!(
        Request::decode(Frame::decode(&b[..n])?, FamilyProfile::LINUX),
        Err(Error::Unsupported)
    );
    b[n - 1] = b'x';
    assert_eq!(
        Request::decode(Frame::decode(&b[..n])?, P),
        Err(Error::Malformed)
    );
    assert_eq!(
        Request::forward(WireId([0; 4]), Family::Any, b"bad\0name"),
        Err(Error::InvalidInput)
    );
    let before = b;
    assert_eq!(
        reply(WireId([0; 4]), Reply::Hostname(b"a\0b"), &mut b),
        Err(Error::InvalidInput)
    );
    assert_eq!(before, b);
    let short = Frame::new(message_type::RESOLVER_REQUEST, &[0; 11])?;
    assert_eq!(Request::decode(short, P), Err(Error::Truncated));
    assert_eq!(Response::decode(short), Err(Error::Unsupported));
    assert_eq!(
        Response::decode(Frame::new(message_type::RESOLVER_RESPONSE, &[0; 3])?),
        Err(Error::Truncated)
    );
    Ok(())
}
#[test]
fn reverse_nonzero_direction_and_embedded_c_string_nul_are_retained() -> TestResult {
    let mut b = [0; 40];
    let n = Request::reverse(WireId([7; 4]), V4).encode(P, &mut b)?;
    b[7] = 9;
    let q = Request::decode(Frame::decode(&b[..n])?, P)?;
    assert_eq!(q.raw_direction(), 9);
    let mut out = [0; 40];
    assert_eq!(q.encode(P, &mut out)?, n);
    assert_eq!(&out[..n], &b[..n]);
    let mut frame = [0; 14];
    MessageHeader::from_total_size(message_type::RESOLVER_RESPONSE, 14)?.encode(&mut frame)?;
    frame[4..8].copy_from_slice(&[7; 4]);
    frame[8..].copy_from_slice(b"a\0bad\0");
    assert_eq!(
        Response::decode(Frame::decode(&frame)?)?.hostname()?,
        Some(b"a".as_slice())
    );
    Ok(())
}
#[test]
fn numeric_and_loopback_events_match_normal_c_order_and_can_cancel_between_values() -> TestResult {
    let mut h = ResolverHandle::<2, 32>::new(P, false)?;
    let id = h.ip_get(
        b"LoCaLhOsT",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(10),
    )?;
    assert_eq!(h.next_wakeup(), Some(AbsoluteTime::from_micros(0)));
    assert!(!h.connection_needed(AbsoluteTime::from_micros(10)));
    // Source add_now has already queued this callback; rollback cannot suspend it.
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(9)),
        Some(Event::Address {
            request: id,
            address: V6
        })
    );
    assert!(h.callbacks_enabled(id));
    h.request_cancel(id, AbsoluteTime::from_micros(10))?;
    assert_eq!(h.next_event(AbsoluteTime::from_micros(10)), None);
    assert!(!h.owns_request(id));
    assert_eq!(
        h.request_cancel(id, AbsoluteTime::from_micros(10)),
        Err(Error::StaleGeneration)
    );
    let id = h.ip_get(
        b"127.0.0.1",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(20),
    )?;
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(20)),
        Some(Event::Address {
            request: id,
            address: V4
        })
    );
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(20)),
        Some(Event::Complete {
            request: id,
            reason: Completion::End
        })
    );
    assert!(!h.owns_request(id));
    assert_eq!(
        h.request_cancel(id, AbsoluteTime::from_micros(20)),
        Err(Error::StaleGeneration)
    );
    Ok(())
}
#[test]
fn zero_deadline_fastpaths_and_numeric_reverse_config_asymmetry_are_real() -> TestResult {
    let mut h = ResolverHandle::<2, 32>::new(P, false)?;
    assert_eq!(
        h.ip_get(
            b"127.0.0.1",
            Family::V6,
            Duration(1),
            AbsoluteTime::from_micros(0)
        ),
        Err(Error::Unavailable)
    );
    assert_eq!(
        h.hostname_get(V4, false, Duration(0), AbsoluteTime::from_micros(0)),
        Err(Error::Unavailable)
    );
    h.connect(true);
    let id = h.hostname_get(V6, false, Duration(0), AbsoluteTime::from_micros(0))?;
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(100)),
        Some(Event::Hostname {
            request: id,
            hostname: Hostname::Numeric(V6)
        })
    );
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(100)),
        Some(Event::Complete {
            request: id,
            reason: Completion::End
        })
    );
    Ok(())
}
#[test]
fn fifo_submission_cancel_drain_and_next_head_do_not_invent_cancel_frames() -> TestResult {
    let mut h = ResolverHandle::<3, 32>::new(P, true)?;
    let a = remote(&mut h, b"a.invalid", 50_000)?;
    let b = remote(&mut h, b"b.invalid", 50_000)?;
    assert!(!h.connection_needed(AbsoluteTime::from_micros(999)));
    let mut out = [0; 80];
    let (e, wire) = start(&mut h, 1_000, &mut out)?;
    let immutable = out;
    assert_eq!(
        h.next_request(e, &mut out, AbsoluteTime::from_micros(1_000)),
        Err(Error::WouldBlock)
    );
    h.request_cancel(a, AbsoluteTime::from_micros(1_001))?;
    assert!(h.owns_request(a));
    assert!(!h.callbacks_enabled(a));
    assert_eq!(out, immutable);
    assert_eq!(
        h.next_request(e, &mut out, AbsoluteTime::from_micros(1_002)),
        Err(Error::WouldBlock)
    );
    let mut raw = [0; 64];
    let n = reply(wire, Reply::Address(V4), &mut raw)?;
    assert_eq!(
        h.receive(
            e,
            Frame::decode(&raw[..n])?,
            AbsoluteTime::from_micros(1_003)
        )?,
        None
    );
    let n = reply(wire, Reply::End, &mut raw)?;
    assert_eq!(
        h.receive(
            e,
            Frame::decode(&raw[..n])?,
            AbsoluteTime::from_micros(1_004)
        )?,
        None
    );
    assert!(!h.owns_request(a));
    assert_eq!(h.next_event(AbsoluteTime::from_micros(1_004)), None);
    assert_eq!(
        h.next_request(e, &mut out, AbsoluteTime::from_micros(1_004))?
            .request,
        b
    );
    Ok(())
}
#[test]
fn all_sent_cancels_close_after_one_ms_and_retire_only_owned_epoch() -> TestResult {
    let mut h = ResolverHandle::<1, 32>::new(P, true)?;
    let id = remote(&mut h, b"x.invalid", 1_000_000)?;
    let mut out = [0; 64];
    let (e, wire) = start(&mut h, 1_000, &mut out)?;
    h.request_cancel(id, AbsoluteTime::from_micros(2_000))?;
    assert_eq!(h.next_wakeup(), Some(AbsoluteTime::from_micros(3_000)));
    assert_eq!(h.poll_idle_close(AbsoluteTime::from_micros(2_999)), None);
    assert!(h.owns_request(id));
    assert_eq!(h.poll_idle_close(AbsoluteTime::from_micros(3_000)), Some(e));
    assert!(!h.owns_request(id));
    let n = reply(wire, Reply::End, &mut out)?;
    assert_eq!(
        h.receive(
            e,
            Frame::decode(&out[..n])?,
            AbsoluteTime::from_micros(3_000)
        ),
        Err(Error::StaleGeneration)
    );
    Ok(())
}
#[test]
fn reconnect_reuses_id_and_original_deadline_and_rejects_stale_epoch() -> TestResult {
    let mut h = ResolverHandle::<1, 32>::new(P, true)?;
    let id = remote(&mut h, b"x.invalid", 10_000)?;
    let mut out = [0; 64];
    let (e, wire) = start(&mut h, 1_000, &mut out)?;
    let first = out;
    h.connection_lost(e, AbsoluteTime::from_micros(2_000))?;
    assert_eq!(h.request_deadline(id)?, AbsoluteTime::from_micros(10_000));
    assert!(!h.connection_needed(AbsoluteTime::from_micros(3_999)));
    let (second, wire2) = start(&mut h, 4_000, &mut out)?;
    assert_ne!(e, second);
    assert_eq!(wire2, wire);
    assert_eq!(out, first);
    assert_eq!(
        h.connection_lost(e, AbsoluteTime::from_micros(4_000)),
        Err(Error::StaleGeneration)
    );
    assert_eq!(h.connection_epoch(), Some(second));
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(10_000)),
        Some(Event::Complete {
            request: id,
            reason: Completion::Timeout
        })
    );
    assert!(!h.owns_request(id));
    Ok(())
}
#[test]
fn unknown_id_reconnects_but_preserves_live_operation_and_same_wire_id() -> TestResult {
    let mut h = ResolverHandle::<1, 32>::new(P, true)?;
    let id = remote(&mut h, b"x.invalid", 20_000)?;
    let mut out = [0; 64];
    let (e, wire) = start(&mut h, 1_000, &mut out)?;
    let n = reply(WireId([99; 4]), Reply::End, &mut out)?;
    assert_eq!(
        h.receive(
            e,
            Frame::decode(&out[..n])?,
            AbsoluteTime::from_micros(2_000)
        ),
        Err(Error::Malformed)
    );
    assert!(h.owns_request(id));
    assert_eq!(h.next_event(AbsoluteTime::from_micros(2_000)), None);
    let (_, wire2) = start(&mut h, 4_000, &mut out)?;
    assert_eq!(wire, wire2);
    Ok(())
}
#[test]
fn end_and_timeout_reverse_fallback_allow_cancel_before_terminal() -> TestResult {
    for timeout in [false, true] {
        let mut h = ResolverHandle::<1, 0>::new(P, true)?;
        let id = h.hostname_get(V4, true, Duration(5_000), AbsoluteTime::from_micros(0))?;
        let mut out = [0; 64];
        let (e, wire) = start(&mut h, 1_000, &mut out)?;
        if !timeout {
            let n = reply(wire, Reply::End, &mut out)?;
            assert_eq!(
                h.receive(
                    e,
                    Frame::decode(&out[..n])?,
                    AbsoluteTime::from_micros(2_000)
                )?,
                None
            );
        }
        let now = AbsoluteTime::from_micros(if timeout { 5_000 } else { 2_000 });
        assert_eq!(
            h.next_event(now),
            Some(Event::Hostname {
                request: id,
                hostname: Hostname::Numeric(V4)
            })
        );
        h.request_cancel(id, now)?;
        assert_eq!(h.next_event(now), None);
        assert!(!h.owns_request(id));
    }
    Ok(())
}
#[test]
fn received_reverse_name_survives_reconnect_and_suppresses_timeout_fallback() -> TestResult {
    let mut h = ResolverHandle::<1, 0>::new(P, true)?;
    let id = h.hostname_get(V4, true, Duration(10_000), AbsoluteTime::from_micros(0))?;
    let mut out = [0; 64];
    let (e, wire) = start(&mut h, 1_000, &mut out)?;
    let n = reply(wire, Reply::Hostname(b"localhost"), &mut out)?;
    assert_eq!(
        h.receive(
            e,
            Frame::decode(&out[..n])?,
            AbsoluteTime::from_micros(2_000)
        )?,
        Some(Event::Hostname {
            request: id,
            hostname: Hostname::Resolved(b"localhost")
        })
    );
    h.connection_lost(e, AbsoluteTime::from_micros(3_000))?;
    let (_, wire2) = start(&mut h, 5_000, &mut out)?;
    assert_eq!(wire, wire2);
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(10_000)),
        Some(Event::Complete {
            request: id,
            reason: Completion::Timeout
        })
    );
    assert_eq!(h.next_event(AbsoluteTime::from_micros(10_000)), None);
    Ok(())
}
#[test]
fn malformed_identified_payload_ends_only_that_request_and_reconnects_next() -> TestResult {
    let mut h = ResolverHandle::<2, 32>::new(P, true)?;
    let first = remote(&mut h, b"a.invalid", 50_000)?;
    let second = remote(&mut h, b"b.invalid", 50_000)?;
    let mut out = [0; 64];
    let (e, wire) = start(&mut h, 1_000, &mut out)?;
    MessageHeader::from_total_size(message_type::RESOLVER_RESPONSE, 13)?.encode(&mut out)?;
    out[4..8].copy_from_slice(&wire.0);
    out[8..13].copy_from_slice(&[1; 5]);
    assert_eq!(
        h.receive(
            e,
            Frame::decode(&out[..13])?,
            AbsoluteTime::from_micros(2_000)
        ),
        Err(Error::Malformed)
    );
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(2_000)),
        Some(Event::Complete {
            request: first,
            reason: Completion::Malformed
        })
    );
    assert!(h.owns_request(second));
    assert_eq!(
        start(&mut h, 4_000, &mut out)?.0,
        h.connection_epoch().ok_or(Error::NotReady)?
    );
    Ok(())
}
#[test]
fn queue_timeouts_are_per_admission_and_receive_at_deadline_cannot_deliver_value() -> TestResult {
    let mut h = ResolverHandle::<2, 32>::new(P, true)?;
    let first = remote(&mut h, b"a.invalid", 10_000)?;
    let second = remote(&mut h, b"b.invalid", 2_000)?;
    let mut out = [0; 64];
    let (e, wire) = start(&mut h, 1_000, &mut out)?;
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(2_000)),
        Some(Event::Complete {
            request: second,
            reason: Completion::Timeout
        })
    );
    assert!(h.owns_request(first));
    let n = reply(wire, Reply::Address(V4), &mut out)?;
    assert_eq!(
        h.receive(
            e,
            Frame::decode(&out[..n])?,
            AbsoluteTime::from_micros(10_000)
        ),
        Err(Error::Deadline)
    );
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(10_000)),
        Some(Event::Complete {
            request: first,
            reason: Completion::Timeout
        })
    );
    Ok(())
}
#[test]
fn admission_output_capacity_and_completion_reservations_are_atomic() -> TestResult {
    let mut h = ResolverHandle::<1, 10>::new(P, true)?;
    assert_eq!(
        h.ip_get(
            b"too-long-name",
            Family::Any,
            Duration(4_000),
            AbsoluteTime::from_micros(0)
        ),
        Err(Error::Capacity)
    );

    assert_eq!(h.pending_requests(), 0);
    let id = remote(&mut h, b"a.invalid", 5_000)?;
    assert_eq!(id.resource_id().generation, 0);
    assert_eq!(remote(&mut h, b"b.invalid", 5_000), Err(Error::Capacity));
    let e = h.begin_connection(AbsoluteTime::from_micros(1_000))?;
    let mut short = [0xA5; 4];
    assert_eq!(
        h.next_request(e, &mut short, AbsoluteTime::from_micros(1_000)),
        Err(Error::Capacity)
    );
    assert_eq!(short, [0xA5; 4]);
    let mut out = [0; 64];
    let q = h.next_request(e, &mut out, AbsoluteTime::from_micros(1_000))?;
    assert_eq!(q.wire_id, WireId::from_native(1));
    let n = reply(q.wire_id, Reply::End, &mut out)?;
    h.receive(
        e,
        Frame::decode(&out[..n])?,
        AbsoluteTime::from_micros(2_000),
    )?;
    assert_eq!(remote(&mut h, b"b.invalid", 5_000), Err(Error::Capacity));
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(2_000)),
        Some(Event::Complete {
            request: id,
            reason: Completion::End
        })
    );
    let next = remote(&mut h, b"b.invalid", 5_000)?;
    assert_ne!(id, next);
    assert_eq!(
        h.request_cancel(id, AbsoluteTime::from_micros(2_000)),
        Err(Error::StaleGeneration)
    );
    Ok(())
}
#[test]
fn disconnect_requires_live_remote_cancellation_but_does_not_cancel_local_tasks() -> TestResult {
    let mut h = ResolverHandle::<2, 32>::new(P, true)?;
    let remote = remote(&mut h, b"a.invalid", 5_000)?;
    let local = h.ip_get(
        b"127.0.0.1",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(0),
    )?;
    assert_eq!(h.disconnect(), Err(Error::WouldBlock));
    h.request_cancel(remote, AbsoluteTime::from_micros(0))?;
    assert_eq!(h.disconnect()?, None);
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(0)),
        Some(Event::Address {
            request: local,
            address: V4
        })
    );
    assert_eq!(
        h.next_event(AbsoluteTime::from_micros(0)),
        Some(Event::Complete {
            request: local,
            reason: Completion::End
        })
    );
    Ok(())
}
#[test]
fn forward_response_family_is_from_payload_length_as_in_c_not_query_filter() -> TestResult {
    let mut h = ResolverHandle::<1, 32>::new(P, true)?;
    let id = h.ip_get(
        b"a.invalid",
        Family::V4,
        Duration(5_000),
        AbsoluteTime::from_micros(0),
    )?;
    let mut out = [0; 64];
    let (e, wire) = start(&mut h, 1_000, &mut out)?;
    let n = reply(wire, Reply::Address(V6), &mut out)?;
    let event = h.receive(
        e,
        Frame::decode(&out[..n])?,
        AbsoluteTime::from_micros(2_000),
    )?;
    assert_eq!(
        event,
        Some(Event::Address {
            request: id,
            address: V6
        })
    );
    h.request_cancel(id, AbsoluteTime::from_micros(2_000))?;
    assert!(!h.callbacks_enabled(id));
    Ok(())
}

#[test]
fn forever_and_finite_overflow_saturate_without_expiring_at_max_clock() -> TestResult {
    for timeout in [u64::MAX, u64::MAX - 9] {
        let mut h = ResolverHandle::<1, 16>::new(P, true)?;
        let id = h.ip_get(
            b"a.invalid",
            Family::Any,
            Duration(timeout),
            AbsoluteTime::from_micros(10),
        )?;
        assert_eq!(h.request_deadline(id)?, AbsoluteTime::from_micros(u64::MAX));
        assert_eq!(h.next_event(AbsoluteTime::from_micros(u64::MAX)), None);
        let mut out = [0; 64];
        let (e, wire) = start(&mut h, 1_010, &mut out)?;
        assert_eq!(h.next_wakeup(), None);
        let n = reply(wire, Reply::Address(V4), &mut out)?;
        assert_eq!(
            h.receive(
                e,
                Frame::decode(&out[..n])?,
                AbsoluteTime::from_micros(u64::MAX)
            )?,
            Some(Event::Address {
                request: id,
                address: V4
            })
        );
        h.request_cancel(id, AbsoluteTime::from_micros(u64::MAX))?;
        assert_eq!(h.next_wakeup(), None);
    }
    Ok(())
}

#[test]
fn unavailable_mq_configuration_retries_without_consuming_epoch_or_deadline() -> TestResult {
    let mut h = ResolverHandle::<1, 16>::new(P, true)?;
    let id = remote(&mut h, b"a.invalid", 10_000)?;
    assert_eq!(
        h.connection_unavailable(AbsoluteTime::from_micros(999)),
        Err(Error::WouldBlock)
    );
    h.connection_unavailable(AbsoluteTime::from_micros(1_000))?;
    assert_eq!(h.connection_epoch(), None);
    assert_eq!(h.next_wakeup(), Some(AbsoluteTime::from_micros(3_000)));
    assert_eq!(h.request_deadline(id)?, AbsoluteTime::from_micros(10_000));
    let mut out = [0; 64];
    let (epoch, wire) = start(&mut h, 3_000, &mut out)?;
    assert_eq!(epoch.value(), 1);
    assert_eq!(wire, WireId::from_native(1));
    Ok(())
}

#[test]
fn local_ready_registration_survives_rollback_and_retains_enqueue_fifo() -> TestResult {
    let mut handle = ResolverHandle::<4, 32>::new(P, true)?;
    let first = handle.ip_get(
        b"127.0.0.1",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(1000),
    )?;
    let second = handle.ip_get(
        b"127.0.0.2",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(500),
    )?;
    let wake = handle.next_wakeup();
    assert!(
        matches!(handle.next_event(AbsoluteTime::from_micros(250)),Some(Event::Address {request,..}) if request==first)
    );
    assert_eq!(
        wake,
        Some(AbsoluteTime::from_micros(0)),
        "already-ready source tasks have an immediate wake hint"
    );
    assert_eq!(
        handle.next_event(AbsoluteTime::from_micros(200)),
        Some(Event::Complete {
            request: first,
            reason: Completion::End
        })
    );
    assert!(
        matches!(handle.next_event(AbsoluteTime::from_micros(100)),Some(Event::Address {request,..}) if request==second)
    );
    assert_eq!(
        handle.next_event(AbsoluteTime::from_micros(50)),
        Some(Event::Complete {
            request: second,
            reason: Completion::End
        })
    );
    Ok(())
}
#[test]
fn zero_remote_timeout_stays_ready_without_replacing_original_deadline() -> TestResult {
    let mut handle = ResolverHandle::<2, 32>::new(P, true)?;
    let id = handle.ip_get(
        b"remote",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(1000),
    )?;
    assert_eq!(
        handle.request_deadline(id)?,
        AbsoluteTime::from_micros(1000)
    );
    let wake = handle.next_wakeup();
    assert_eq!(
        handle.next_event(AbsoluteTime::from_micros(500)),
        Some(Event::Complete {
            request: id,
            reason: Completion::Timeout
        })
    );
    assert_eq!(wake, Some(AbsoluteTime::from_micros(0)));
    assert!(!handle.owns_request(id));
    Ok(())
}
#[test]
fn local_tasks_are_ready_even_at_never_but_remote_never_is_not_due() -> TestResult {
    let mut handle = ResolverHandle::<3, 32>::new(P, true)?;
    let local = handle.ip_get(
        b"127.0.0.1",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(u64::MAX),
    )?;
    let remote = handle.ip_get(
        b"remote",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(u64::MAX),
    )?;
    assert_eq!(
        handle.request_deadline(remote)?,
        AbsoluteTime::from_micros(u64::MAX)
    );
    assert!(
        matches!(handle.next_event(AbsoluteTime::from_micros(0)),Some(Event::Address {request,..}) if request==local)
    );
    assert_eq!(
        handle.next_event(AbsoluteTime::from_micros(0)),
        Some(Event::Complete {
            request: local,
            reason: Completion::End
        })
    );
    assert_eq!(handle.next_event(AbsoluteTime::from_micros(0)), None);
    assert!(handle.owns_request(remote));
    Ok(())
}

#[test]
fn local_ready_fifo_uses_registration_order_after_clock_rollback() -> TestResult {
    let mut handle = ResolverHandle::<2, 32>::new(P, true)?;
    let first = handle.ip_get(
        b"127.0.0.1",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(1000),
    )?;
    let second = handle.ip_get(
        b"127.0.0.2",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(500),
    )?;
    assert_ne!(first, second);
    assert!(
        matches!(handle.next_event(AbsoluteTime::from_micros(2000)),Some(Event::Address {request,..}) if request==first)
    );
    Ok(())
}

#[test]
fn positive_remote_delay_keeps_original_deadline_across_rollback() -> TestResult {
    let mut handle = ResolverHandle::<2, 32>::new(P, true)?;
    let request = handle.ip_get(
        b"remote",
        Family::Any,
        Duration(1000),
        AbsoluteTime::from_micros(1000),
    )?;
    assert_eq!(
        handle.request_deadline(request)?,
        AbsoluteTime::from_micros(2000)
    );
    assert_eq!(handle.next_event(AbsoluteTime::from_micros(500)), None);
    assert_eq!(handle.next_event(AbsoluteTime::from_micros(1999)), None);
    assert_eq!(
        handle.next_event(AbsoluteTime::from_micros(2000)),
        Some(Event::Complete {
            request,
            reason: Completion::Timeout
        })
    );
    Ok(())
}
