//! Actual Rust pending-action trace compared with original pinned C functions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Differential queue test compares independently executed original C action snapshots"
)]
use gnunet_client::{
    statistics::Selector,
    statistics_handle::{GetId, OutboundKind, StatisticsHandle},
};
use gnunet_types::{AbsoluteTime, Error};
use std::fmt::Write;
type H<'owner> = StatisticsHandle<'owner, 32, 128, 4, 32, 32>;
fn hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
fn snapshot<'owner>(
    label: &str,
    h: &mut H<'owner>,
    e: gnunet_client::statistics_handle::ConnectionEpoch<'owner>,
    trace: &mut String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut count = 0;
    loop {
        let mut out = [0; 256];
        let Some(frame) = h.next_request(e, &mut out)? else {
            break;
        };
        let (kind, value, persistent, start) = match frame.kind {
            OutboundKind::Mutation {
                relative,
                persistent,
            } => (
                if relative { "update" } else { "set" },
                u64::from_be_bytes(out[8..16].try_into()?),
                u8::from(persistent),
                16,
            ),
            OutboundKind::Get(_) => ("get", 0, 0, 4),
            _ => return Err(Error::Unsupported.into()),
        };
        let names = &out[start..frame.len];
        let split = names.iter().position(|b| *b == 0).ok_or(Error::Malformed)?;
        writeln!(
            trace,
            "action|{label}|{kind}|{}|{}|{value}|{persistent}",
            hex(&names[..split]),
            hex(&names[split + 1..names.len() - 1])
        )?;
        h.on_frame_written(e, frame.transmit)?;
        if matches!(frame.kind, OutboundKind::Get(_)) {
            h.receive(e, b"\0\x04\0\xab", AbsoluteTime::from_micros(0))?;
            h.take_completion();
        }
        count += 1;
    }
    if count == 0 {
        writeln!(trace, "empty|{label}")?;
    }
    Ok(())
}
#[test]
fn original_c_pending_queue_coalescing_matches_rust() -> Result<(), Box<dyn std::error::Error>> {
    let mut trace = String::new();

    {
        let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_1, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        h.set(b"a", 20u64, false)?;
        h.get(Selector {
            subsystem: b"s",
            name: b"a",
        })?;
        h.update(b"a", -30i64, true)?;
        h.update(b"a", 10i64, false)?;
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("saturation-across-get", &mut h, e, &mut trace)?;
    }

    {
        let mut statistics_instance_2 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_2, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        h.update(b"a", -1i64, false)?;
        h.update(b"a", 1i64, true)?;
        h.update(b"a", 0i64, false)?;
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("zero-merged-update", &mut h, e, &mut trace)?;
    }

    {
        let mut statistics_instance_3 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_3, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        h.update(b"a", 0i64, true)?;
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("zero-call-no-action", &mut h, e, &mut trace)?;
    }

    {
        let mut statistics_instance_4 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_4, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        h.update(b"a", 7i64, true)?;
        h.set(b"a", 9u64, false)?;
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("replace-update-with-set", &mut h, e, &mut trace)?;
    }

    {
        let mut statistics_instance_5 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_5, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        h.set(b"a", 1u64, false)?;
        h.get(Selector {
            subsystem: b"other",
            name: b"x",
        })?;
        h.set(b"A", 2u64, false)?;
        h.update(b"a", 4i64, true)?;
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("case-sensitive-names", &mut h, e, &mut trace)?;
    }

    {
        let mut statistics_instance_6 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_6, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        h.set(b"a", 1u64, false)?;
        h.set(b"b", 2u64, false)?;
        h.set(b"a", 3u64, true)?;
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("setter-fifo-position", &mut h, e, &mut trace)?;
    }

    {
        let mut statistics_instance_7 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_7, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        let mut gets = Vec::<GetId<'_>>::new();
        h.set(b"a", 1u64, false)?;
        gets.push(h.get(Selector {
            subsystem: b"s",
            name: b"a",
        })?);
        gets.push(h.get(Selector {
            subsystem: b"s",
            name: b"b",
        })?);
        h.get_cancel(gets[0])?;
        h.update(b"a", 2i64, true)?;
        drop(gets);
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("cancel-queued-get", &mut h, e, &mut trace)?;
    }

    {
        let mut statistics_instance_8 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_8, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        h.set(b"a", 9223372036854775813u64, false)?;
        h.update(b"a", -9223372036854775808i64, true)?;
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("negative-minimum", &mut h, e, &mut trace)?;
    }

    {
        let mut statistics_instance_9 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_9, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        h.set(b"a", 18446744073709551615u64, false)?;
        h.update(b"a", 1i64, true)?;
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("positive-wrap", &mut h, e, &mut trace)?;
    }

    {
        let mut statistics_instance_10 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_10, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        h.set(b"a", 1u64, true)?;
        h.update(b"a", -2i64, false)?;
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("negative-clamp", &mut h, e, &mut trace)?;
    }

    {
        let mut statistics_instance_11 = gnunet_client::statistics_handle::Instance::new();
        let mut h = H::new(&mut statistics_instance_11, b"s", true)?.ok_or(Error::Unavailable)?;
        h.set(b"_anchor", 0, false)?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        let anchor = h.next_request(e, &mut [0; 256])?.ok_or(Error::NotReady)?;
        h.get(Selector {
            subsystem: b"",
            name: b"",
        })?;
        h.on_frame_written(e, anchor.transmit)?;
        snapshot("get-wildcards", &mut h, e, &mut trace)?;
    }
    let mut statistics_instance_12 = gnunet_client::statistics_handle::Instance::new();
    writeln!(
        trace,
        "disabled|{}",
        u8::from(H::new(&mut statistics_instance_12, b"ignored", false)?.is_none())
    )?;
    assert_eq!(trace, include_str!("fixtures/handle_queue.txt"));
    if let Some(path) = std::env::var_os("GNUNET_HANDLE_QUEUE_TRACE") {
        std::fs::write(path, trace)?;
    }
    Ok(())
}
