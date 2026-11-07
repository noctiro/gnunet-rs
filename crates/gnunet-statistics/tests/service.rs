//! Official service behavior, independent protocol literals and bounded-resource tests.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report independently derived protocol and service invariants"
)]

use gnunet_statistics::{
    ClientId, Notification, Reply, Request, SET_PERSISTENT, SET_RELATIVE, Selector, Set,
    Statistics, encode_disconnect_confirmation,
};
use gnunet_types::Error;

const ALL: Selector<'static> = Selector {
    subsystem: b"",
    name: b"",
};
const A: Selector<'static> = Selector {
    subsystem: b"s",
    name: b"a",
};

fn set(selector: Selector<'_>, flags: u32, value: u64) -> Set<'_> {
    Set {
        selector,
        flags,
        value,
    }
}

fn message(trace: &mut String, client: u32, bytes: &[u8]) {
    trace.push_str(&format!("message {client} {}\n", hex(bytes)));
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::new();
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

struct Trace {
    state: Statistics<8, 32, 2, 8, 16>,
    clients: [ClientId; 2],
    text: String,
}

impl Trace {
    fn new() -> Result<Self, Error> {
        let mut state = Statistics::new();
        let clients = [state.connect()?, state.connect()?];
        Ok(Self {
            state,
            clients,
            text: String::new(),
        })
    }
    fn drain(&mut self) -> Result<(), Error> {
        while let Some(notification) = self.state.notification().copied() {
            let mut frame = [0; 24];
            notification.encode(&mut frame)?;
            message(
                &mut self.text,
                notification.client.resource_id().index,
                &frame,
            );
            assert_eq!(self.state.consume_notification(), Some(notification));
        }
        Ok(())
    }
    fn set(
        &mut self,
        client: usize,
        selector: Selector<'_>,
        flags: u32,
        value: u64,
    ) -> Result<(), Error> {
        let outcome = self
            .state
            .set(self.clients[client], set(selector, flags, value))?;
        self.drain()?;
        self.text.push_str(&format!(
            "set {} {} {} {}\n",
            outcome.uid,
            outcome.value,
            u8::from(outcome.is_set),
            u8::from(outcome.persistent)
        ));
        Ok(())
    }
    fn watch(&mut self, client: usize, selector: Selector<'_>) -> Result<(), Error> {
        let wid = self.state.watch(self.clients[client], selector)?;
        self.drain()?;
        self.text.push_str(&format!("watch {client} {wid}\n"));
        Ok(())
    }
    fn get(&mut self, client: usize, selector: Selector<'_>) -> Result<(), Error> {
        for reply in self.state.get(self.clients[client], selector)? {
            let mut output = [0; 64];
            let len = reply.encode(&mut output)?;
            message(&mut self.text, client as u32, &output[..len]);
        }
        Ok(())
    }
}

#[test]
fn matches_original_c_service_handlers_and_both_c_arithmetic_profiles() -> Result<(), Error> {
    let mut trace = Trace::new()?;
    trace.watch(0, A)?;
    trace.set(1, A, 2, 0)?;
    trace.set(1, A, 0, 0)?;
    trace.watch(0, A)?;
    trace.set(1, A, 1, 0)?;
    trace.set(1, A, 2, 5)?;
    trace.watch(1, A)?;
    trace.set(1, A, 3, (-7_i64) as u64)?;
    trace.set(1, A, 1, u64::MAX)?;
    trace.set(1, A, 2, u64::MAX)?;
    trace.set(1, A, 1, 1)?;
    trace.set(1, A, 1, 0x8000_0000_0000_0000)?;
    trace.set(1, A, 0, 0x8000_0000_0000_0005)?;
    trace.set(1, A, 1, 0x8000_0000_0000_0000)?;
    trace.set(1, A, 1, i64::MAX as u64)?;
    let t = Selector {
        subsystem: b"t",
        name: b"n",
    };
    let z = Selector {
        subsystem: b"s",
        name: b"z",
    };
    trace.set(1, t, 1, (-2_i64) as u64)?;
    trace.set(1, z, 1, 0)?;
    trace.get(0, ALL)?;
    trace.set(1, t, 1, 0)?;
    trace.set(1, z, 0, 3)?;
    trace.set(1, A, 2, 5)?;
    trace.set(1, z, 0, 3)?;
    trace.get(
        0,
        Selector {
            subsystem: b"",
            name: b"a",
        },
    )?;
    trace.get(
        0,
        Selector {
            subsystem: b"s",
            name: b"",
        },
    )?;
    trace.get(
        0,
        Selector {
            subsystem: b"",
            name: b"missing",
        },
    )?;
    trace.state.disconnect(trace.clients[0])?;
    trace.text.push_str("disconnect 0\n");
    trace.set(1, A, 0, 7)?;
    trace.watch(1, ALL)?;
    trace.set(1, ALL, 2, 0)?;
    trace.get(1, ALL)?;
    let mut frame = [0; 4];
    encode_disconnect_confirmation(&mut frame)?;
    message(&mut trace.text, 1, &frame);
    assert_eq!(trace.text, include_str!("fixtures/service_trace.txt"));
    if let Some(path) = std::env::var_os("GNUNET_STATISTICS_TRACE") {
        std::fs::write(path, trace.text.as_bytes()).map_err(|_| Error::Io)?;
    }
    Ok(())
}

#[test]
fn independent_wire_literals_and_exact_request_boundaries() -> Result<(), Error> {
    let bytes = b"\0\x14\0\xa8\0\0\0\x03\xff\xff\xff\xff\xff\xff\xff\xf9s\0a\0";
    assert_eq!(
        Request::decode(bytes)?,
        Request::Set(set(A, 3, (-7_i64) as u64))
    );
    for end in 0..bytes.len() {
        assert!(Request::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(Request::decode(&trailing).is_err());
    assert_eq!(Request::decode(b"\0\x08\0\xa9s\0a\0")?, Request::Get(A));
    assert_eq!(Request::decode(b"\0\x06\0\xac\0\0")?, Request::Watch(ALL));
    assert_eq!(Request::decode(b"\0\x04\0\xae")?, Request::Disconnect);
    assert!(Request::decode(b"\0\x05\0\xae\0").is_err());
    assert!(Request::decode(b"\0\x07\0\xa9s\0a").is_err());
    assert!(Request::decode(b"\0\x09\0\xa9s\0a\0\0").is_err());
    assert_eq!(Request::decode(b"\0\x04\0\xab"), Err(Error::Unsupported));
    let mut state: Statistics<1, 4, 1, 1, 1> = Statistics::new();
    let client = state.connect()?;
    state.set(client, set(A, SET_PERSISTENT, 0x0102_0304_0506_0708))?;
    let notification = Notification {
        client,
        wid: 7,
        persistent: true,
        value: 0x0102_0304_0506_0708,
    };
    let mut output = [0xa5; 64];
    assert_eq!(notification.encode(&mut output[..23]), Err(Error::Capacity));
    assert_eq!(output, [0xa5; 64]);
    assert_eq!(notification.encode(&mut output)?, 24);
    assert_eq!(
        &output[..24],
        b"\0\x18\0\xad\0\0\0\x02\0\0\0\x07\0\0\0\0\x01\x02\x03\x04\x05\x06\x07\x08"
    );
    let mut replies = state.get(client, A)?;
    let reply = replies.next().ok_or(Error::NotFound)?;
    output.fill(0xa5);
    assert_eq!(reply.encode(&mut output[..19]), Err(Error::Capacity));
    assert_eq!(output, [0xa5; 64]);
    let len = reply.encode(&mut output)?;
    assert_eq!(
        &output[..len],
        b"\0\x14\0\xaa\x80\0\0\0\x01\x02\x03\x04\x05\x06\x07\x08s\0a\0"
    );
    assert_eq!(replies.next(), Some(Reply::End));
    assert_eq!(replies.next(), None);
    assert_eq!(replies.next(), None);
    Ok(())
}

#[test]
fn zero_watch_and_initial_set_are_distinct_from_equal_value_updates() -> Result<(), Error> {
    let mut state: Statistics<2, 4, 1, 3, 4> = Statistics::new();
    let client = state.connect()?;
    let first = state.set(client, set(A, SET_RELATIVE, u64::MAX))?;
    assert!(!first.is_set);
    assert_eq!(first.value, 0);
    assert_eq!(state.watch(client, A)?, 0);
    assert!(state.notification().is_none());
    let outcome = state.set(client, set(A, SET_RELATIVE, 0))?;
    assert!(outcome.is_set);
    assert_eq!(outcome.notifications, 1);
    assert_eq!(
        state.consume_notification().map(|n| (n.wid, n.value)),
        Some((0, 0))
    );
    assert_eq!(state.watch(client, A)?, 1);
    assert!(state.notification().is_none());
    assert_eq!(
        state.set(client, set(A, SET_PERSISTENT, 0))?.notifications,
        0
    );
    let changes = state.set(client, set(A, SET_PERSISTENT | SET_RELATIVE, 2))?;
    assert_eq!(changes.notifications, 2);
    assert_eq!(
        state
            .consume_notification()
            .map(|n| (n.wid, n.value, n.persistent)),
        Some((1, 2, true))
    );
    assert_eq!(
        state
            .consume_notification()
            .map(|n| (n.wid, n.value, n.persistent)),
        Some((0, 2, true))
    );
    assert_eq!(state.set(client, set(A, 0x8000_0000, 2))?.notifications, 0);
    let Reply::Value(value) = state.get(client, A)?.next().ok_or(Error::NotFound)? else {
        return Err(Error::NotFound);
    };
    assert!(!value.persistent());
    assert_eq!(value.uid(), 0);
    Ok(())
}

#[test]
fn each_capacity_rejection_preserves_ids_rows_and_effects() -> Result<(), Error> {
    let mut none: Statistics<0, 0, 0, 0, 0> = Statistics::new();
    assert_eq!(none.connect(), Err(Error::Capacity));
    let mut state: Statistics<1, 4, 1, 2, 1> = Statistics::new();
    let client = state.connect()?;
    assert_eq!(state.connect(), Err(Error::Capacity));
    let long = Selector {
        subsystem: b"s",
        name: b"long",
    };
    assert_eq!(state.watch(client, long), Err(Error::Capacity));
    assert_eq!(state.row_count(), 0);
    assert_eq!(state.watch_count(), 0);
    assert_eq!(state.watch(client, A)?, 0);
    assert_eq!(state.set(client, set(ALL, 0, 1)), Err(Error::Capacity));
    assert_eq!(state.set(client, set(A, SET_PERSISTENT, 5))?.uid, 0);
    assert_eq!(state.watch(client, A), Err(Error::Capacity));
    assert_eq!(state.watch_count(), 1);
    assert_eq!(state.notification_count_queued(), 1);
    assert_eq!(state.set(client, set(A, 0, 9)), Err(Error::Capacity));
    let Reply::Value(value) = state.get(client, A)?.next().ok_or(Error::NotFound)? else {
        return Err(Error::NotFound);
    };
    assert_eq!((value.value, value.persistent()), (5, true));
    assert_eq!(state.consume_notification().map(|n| n.value), Some(5));
    assert_eq!(state.watch(client, A)?, 1); // Failed WATCH did not consume its WID.
    assert_eq!(state.consume_notification().map(|n| n.wid), Some(1));
    assert_eq!(state.watch(client, A), Err(Error::Capacity));
    assert_eq!(state.set(client, set(A, 0, 9)), Err(Error::Capacity)); // Needs two effects.
    assert_eq!(state.notification_count_queued(), 0);
    let invalid = Selector {
        subsystem: b"s\0",
        name: b"",
    };
    assert_eq!(
        state.set(client, set(invalid, 0, 1)),
        Err(Error::InvalidInput)
    );
    assert_eq!(state.watch_count(), 2);
    assert_eq!(state.row_count(), 1);
    Ok(())
}

#[test]
fn notification_queue_preserves_intermediate_values_until_consumed() -> Result<(), Error> {
    let mut state: Statistics<1, 4, 1, 1, 3> = Statistics::new();
    let client = state.connect()?;
    state.watch(client, A)?;
    for value in 1..=3 {
        state.set(client, set(A, 0, value))?;
    }
    assert_eq!(state.set(client, set(A, 0, 4)), Err(Error::Capacity));
    assert_eq!(state.notification().map(|n| n.value), Some(1));
    let mut short = [0xa5; 23];
    assert_eq!(
        state
            .notification()
            .ok_or(Error::NotFound)?
            .encode(&mut short),
        Err(Error::Capacity)
    );
    assert_eq!(state.notification_count_queued(), 3);
    assert_eq!(state.consume_notification().map(|n| n.value), Some(1));
    state.set(client, set(A, 0, 4))?;
    for value in 2..=4 {
        assert_eq!(state.consume_notification().map(|n| n.value), Some(value));
    }
    assert_eq!(state.consume_notification(), None);
    Ok(())
}

#[test]
fn disconnect_releases_only_its_owner_and_generations_protect_replacements() -> Result<(), Error> {
    let mut state: Statistics<2, 4, 2, 6, 16> = Statistics::new();
    let a = state.connect()?;
    let b = state.connect()?;
    state.watch(a, A)?;
    state.watch(b, A)?;
    state.watch(a, A)?;
    state.watch(b, A)?;
    state.watch(a, ALL)?;
    state.watch(b, ALL)?;
    state.set(b, set(A, SET_PERSISTENT, 7))?;
    state.set(b, set(ALL, 0, 9))?;
    assert_eq!(state.notification_count_queued(), 6);
    state.disconnect(a)?;
    assert_eq!(
        (state.row_count(), state.client_count(), state.watch_count()),
        (2, 1, 3)
    );
    assert_eq!(state.notification_count_queued(), 3);
    let replacement = state.connect()?;
    assert_eq!(a.resource_id().index, replacement.resource_id().index);
    assert_ne!(a, replacement);
    assert_eq!(state.disconnect(a), Err(Error::StaleGeneration));
    assert_eq!(state.watch(a, A), Err(Error::StaleGeneration));
    assert_eq!(state.set(a, set(A, 0, 1)), Err(Error::StaleGeneration));
    assert!(matches!(state.get(a, ALL), Err(Error::StaleGeneration)));
    while let Some(notification) = state.consume_notification() {
        assert_eq!(notification.client, b);
    }
    assert_eq!(state.watch(replacement, A)?, 0);
    assert_eq!(
        state
            .consume_notification()
            .map(|n| (n.client, n.wid, n.value)),
        Some((replacement, 0, 7))
    );
    assert_eq!(state.set(b, set(A, 0, 8))?.notifications, 3);
    let owners: Vec<_> = std::iter::from_fn(|| state.consume_notification())
        .map(|n| n.client)
        .collect();
    assert_eq!(owners, [replacement, b, b]);
    state.disconnect(b)?;
    assert_eq!(state.watch_count(), 1);
    assert_eq!(state.row_count(), 2);
    Ok(())
}

#[test]
fn get_wildcards_are_independent_and_list_order_tracks_c_move_to_front() -> Result<(), Error> {
    let mut state: Statistics<4, 8, 1, 0, 0> = Statistics::new();
    let client = state.connect()?;
    let b = Selector {
        subsystem: b"s",
        name: b"b",
    };
    let t = Selector {
        subsystem: b"t",
        name: b"a",
    };
    state.set(client, set(A, 0, 1))?;
    state.set(client, set(b, 0, 2))?;
    state.set(client, set(t, 0, 3))?;
    state.set(client, set(A, 0, 1))?; // Equal SET still moves the row to front.
    let ids = |selector| -> Result<Vec<u32>, Error> {
        Ok(state
            .get(client, selector)?
            .filter_map(|reply| match reply {
                Reply::Value(row) => Some(row.uid()),
                Reply::End => None,
            })
            .collect())
    };
    assert_eq!(ids(ALL)?, [2, 0, 1]);
    assert_eq!(
        ids(Selector {
            subsystem: b"",
            name: b"a"
        })?,
        [2, 0]
    );
    assert_eq!(
        ids(Selector {
            subsystem: b"s",
            name: b""
        })?,
        [0, 1]
    );
    assert_eq!(
        ids(Selector {
            subsystem: b"missing",
            name: b""
        })?,
        []
    );
    assert_eq!(
        state
            .get(
                client,
                Selector {
                    subsystem: b"a very long missing selector",
                    name: b""
                }
            )?
            .next(),
        Some(Reply::End)
    );
    Ok(())
}

#[test]
fn persistence_is_only_official_set_records_with_a_real_import_contract() -> Result<(), Error> {
    let literal = b"\0\x14\0\xa8\0\0\0\x02\x01\x02\x03\x04\x05\x06\x07\x08s\0a\0";
    let mut state: Statistics<3, 8, 1, 1, 1> = Statistics::new();
    assert_eq!(state.restore(literal)?.value, 0x0102_0304_0506_0708);
    let client = state.connect()?;
    assert_eq!(state.restore(literal), Err(Error::Conflict));
    state.set(client, set(ALL, 0, 3))?;
    let opaque = Selector {
        subsystem: b"\xff",
        name: b"\x80",
    };
    state.set(client, set(opaque, SET_PERSISTENT, u64::MAX))?;
    let persistent: Vec<_> = state.persistent().collect();
    assert_eq!(persistent.len(), 2);
    assert_eq!(persistent[0], set(opaque, SET_PERSISTENT, u64::MAX));
    let mut output = [0xa5; 32];
    let size = persistent[1].encode(&mut output)?;
    assert_eq!(&output[..size], literal);
    state.disconnect(client)?;
    let mut noncanonical = literal.to_vec();
    noncanonical[7] = 3;
    assert_eq!(state.restore(&noncanonical), Err(Error::InvalidInput));
    for prefix in 0..literal.len() {
        assert!(state.restore(&literal[..prefix]).is_err());
    }
    assert_eq!(state.persistent().count(), 2);
    let client = state.connect()?;
    let Reply::Value(row) = state.get(client, opaque)?.next().ok_or(Error::NotFound)? else {
        return Err(Error::NotFound);
    };
    assert_eq!((row.value, row.persistent()), (u64::MAX, true));
    Ok(())
}

#[test]
fn signed_extremes_clamp_and_positive_overflow_wraps_with_a_diagnostic() -> Result<(), Error> {
    let mut state: Statistics<1, 4, 1, 0, 0> = Statistics::new();
    let client = state.connect()?;
    state.set(client, set(A, 0, u64::MAX))?;
    let wrapped = state.set(client, set(A, SET_RELATIVE, 1))?;
    assert_eq!(wrapped.value, 0);
    assert!(wrapped.positive_overflow);
    state.set(client, set(A, 0, 0x8000_0000_0000_0005))?;
    assert_eq!(
        state
            .set(client, set(A, SET_RELATIVE, i64::MIN as u64))?
            .value,
        5
    );
    assert_eq!(
        state
            .set(client, set(A, SET_RELATIVE, (-6_i64) as u64))?
            .value,
        0
    );
    assert_eq!(
        state
            .set(client, set(A, SET_RELATIVE, i64::MAX as u64))?
            .value,
        i64::MAX as u64
    );
    Ok(())
}
